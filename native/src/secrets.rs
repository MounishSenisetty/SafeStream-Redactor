//! The statistical tiers: `EntropyDetector` and `CompoundSecretDetector`
//! (`detectors/entropy.py`).
//!
//! Both tiers find runs over a fixed ASCII alphabet and classify each run by
//! length, character classes and Shannon entropy. The runs and every gate except
//! the entropy are exact integer/ASCII logic. The entropy is a float, and the
//! Python tier computes it with `math.log2` and a `sum()` whose algorithm changed
//! in CPython 3.12 (Neumaier compensation), so a Rust value cannot be guaranteed
//! bit-identical. Instead each entropy result carries an uncertainty band:
//!
//! * any faithful `log2` and either summation land within ~1e-13 of the true
//!   value for these tokens (at most 66 distinct ASCII characters, at most
//!   `MAX_SPAN` long), so
//! * if the Rust value is more than [`BAND`] from a threshold, Python's value is
//!   on the same side, and the verdict is exact; likewise for the two-decimal
//!   `meta["entropy"]` string unless the value sits next to a rounding boundary.
//!
//! A token inside a band is reported as [`Verdict::Undecided`] and the caller
//! classifies (and formats) it in Python. Such tokens are rare (16 distinct
//! characters used equally gives exactly 4.0), so the slow path almost never runs.

use crate::error::{try_push, Error};

/// `entropy.MAX_SPAN`: candidate runs are capped at this many characters.
pub const MAX_SPAN: usize = 8 * 1024;

/// Half-width of the uncertainty band around a threshold (in bits).
const BAND: f64 = 1e-9;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Verdict {
    /// A secret; `entropy` is safe to format with two decimals.
    Secret,
    /// Too close to a threshold or a rounding boundary: decide in Python.
    Undecided,
}

/// One reported run, byte offsets (ASCII, so they equal character offsets
/// within the run; the caller converts the start).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SecretMatch {
    pub start: usize,
    pub end: usize,
    pub entropy: f64,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug)]
pub struct EntropyParams {
    pub min_length: usize,
    pub base64_entropy: f64,
    pub hex_entropy: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct CompoundParams {
    pub min_length: usize,
    pub entropy_floor: f64,
    pub distinct_ratio: f64,
}

/// `[A-Za-z0-9+/=_-]`, the entropy candidate alphabet.
#[inline]
fn base64ish(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// `!#$%^&*~`, the strong password specials.
#[inline]
fn strong_special(b: u8) -> bool {
    matches!(b, b'!' | b'#' | b'$' | b'%' | b'^' | b'&' | b'*' | b'~')
}

/// Shannon entropy in bits per character, from a stack histogram (no allocation).
fn entropy(token: &[u8]) -> f64 {
    let mut counts = [0u32; 128];
    for &b in token {
        counts[usize::from(b & 0x7F)] += 1;
    }
    let n = token.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter().filter(|&&c| c > 0) {
        let p = f64::from(c) / n;
        h -= p * p.log2();
    }
    h
}

/// True when `value >= threshold` is decided with certainty (outside the band).
#[inline]
fn certain(value: f64, threshold: f64) -> bool {
    (value - threshold).abs() > BAND
}

/// True when `f"{value:.2f}"` cannot depend on the last bits of `value`.
#[inline]
fn format_safe(value: f64) -> bool {
    let x = value * 100.0;
    (x - x.floor() - 0.5).abs() > 1e-6
}

/// Every maximal run of `class` bytes, split into consecutive `MAX_SPAN` pieces,
/// keeping pieces of at least 20 bytes: exactly `re.finditer` over
/// `[class]{20,MAX_SPAN}`. Non-ASCII bytes are never in the class.
fn runs(
    text: &[u8],
    class: impl Fn(u8) -> bool,
    mut f: impl FnMut(usize, usize) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut i = 0;
    while i < text.len() {
        if !class(text[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && class(text[i]) {
            i += 1;
        }
        let mut s = start;
        while s < i {
            let e = (s + MAX_SPAN).min(i);
            if e - s >= 20 {
                f(s, e)?;
            }
            s = e;
        }
    }
    Ok(())
}

/// `EntropyDetector.detect`: secrets and undecided candidates, byte offsets.
pub(crate) fn scan_entropy(
    text: &str,
    p: EntropyParams,
    out: &mut Vec<SecretMatch>,
) -> Result<(), Error> {
    let bytes = text.as_bytes();
    runs(bytes, base64ish, |s, e| {
        let token = &bytes[s..e];
        if token.len() < p.min_length || token.iter().all(u8::is_ascii_alphabetic) {
            return Ok(());
        }
        let h = entropy(token);
        let (passes, threshold) = if token.iter().all(u8::is_ascii_hexdigit) {
            if token.len() < 32 {
                return Ok(());
            }
            (h >= p.hex_entropy, p.hex_entropy)
        } else {
            (h >= p.base64_entropy, p.base64_entropy)
        };
        let verdict = if !certain(h, threshold) || !format_safe(h) {
            Verdict::Undecided
        } else if passes {
            Verdict::Secret
        } else {
            return Ok(());
        };
        try_push(
            out,
            SecretMatch {
                start: s,
                end: e,
                entropy: h,
                verdict,
            },
        )
    })
}

/// `CompoundSecretDetector.detect`.
pub(crate) fn scan_compound(
    text: &str,
    p: CompoundParams,
    out: &mut Vec<SecretMatch>,
) -> Result<(), Error> {
    let bytes = text.as_bytes();
    // prefilter, as in Python: no strong special anywhere, no candidate can pass
    if !bytes.iter().copied().any(strong_special) {
        return Ok(());
    }
    runs(
        bytes,
        |b| base64ish(b) || strong_special(b),
        |s, e| {
            let t = &bytes[s..e];
            let n = t.len();
            if n < p.min_length {
                return Ok(());
            }
            // (1) a strong special between two alphanumerics
            let embedded = (1..n - 1).any(|i| {
                strong_special(t[i])
                    && t[i - 1].is_ascii_alphanumeric()
                    && t[i + 1].is_ascii_alphanumeric()
            });
            if !embedded {
                return Ok(());
            }
            // (2) at least two of lowercase / uppercase / digit
            let classes = [
                u8::is_ascii_lowercase,
                u8::is_ascii_uppercase,
                u8::is_ascii_digit,
            ]
            .iter()
            .filter(|f| t.iter().any(f))
            .count();
            if classes < 2 {
                return Ok(());
            }
            // (3) distinct-character ratio (int / int division, exact in both)
            let mut seen = [false; 128];
            let mut distinct = 0usize;
            for &b in t {
                let slot = &mut seen[usize::from(b & 0x7F)];
                if !*slot {
                    *slot = true;
                    distinct += 1;
                }
            }
            if (distinct as f64) / (n as f64) < p.distinct_ratio {
                return Ok(());
            }
            // (4) entropy floor; meta["entropy"] is always set, so format safety too
            let h = entropy(t);
            let verdict = if !certain(h, p.entropy_floor) || !format_safe(h) {
                Verdict::Undecided
            } else if h >= p.entropy_floor {
                Verdict::Secret
            } else {
                return Ok(());
            };
            try_push(
                out,
                SecretMatch {
                    start: s,
                    end: e,
                    entropy: h,
                    verdict,
                },
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_near_and_far_from_the_threshold() {
        let p = EntropyParams {
            min_length: 24,
            base64_entropy: 4.0,
            hex_entropy: 3.0,
        };
        let mut out = Vec::new();
        // 32 distinct characters once each: H = 5 exactly, far above 4.0
        scan_entropy("0123456789ABCDEFghijklmnopqrstuv", p, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].verdict, Verdict::Secret);
        assert!((out[0].entropy - 5.0).abs() < 1e-12);
        // 16 distinct non-hex characters twice each: H = 4.0 exactly, on the
        // threshold, so CPython's float result decides
        out.clear();
        scan_entropy("ghij0123klmn4567ghij0123klmn4567", p, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].verdict, Verdict::Undecided);
        // letters only, or too short: never a candidate
        out.clear();
        scan_entropy("abcdefghijklmnopqrstuvwxyz short1", p, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn runs_split_at_max_span() {
        let text = "A1".repeat(MAX_SPAN) + " x";
        let mut seen = Vec::new();
        runs(text.as_bytes(), base64ish, |s, e| {
            seen.push((s, e));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![(0, MAX_SPAN), (MAX_SPAN, 2 * MAX_SPAN)]);
    }
}
