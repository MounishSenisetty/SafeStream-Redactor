//! The statistical tiers (`detectors/entropy.py`): high-entropy secrets and
//! symbol-containing "compound" secrets, reproduced bit for bit.
//!
//! Both tiers find candidates with an ASCII character class and no lookaround,
//! so a byte scanner replaces the regex. The gates are pure functions of the
//! candidate. The one delicate part is the Shannon entropy, a float sum compared
//! against a threshold. It is reproduced operation for operation:
//!
//! * terms in `collections.Counter` order (first occurrence of each character);
//! * each term `(c / n) * log2(c / n)`: an exact int→float division, then the
//!   platform `log2` (CPython's `math.log2` and Rust's `f64::log2` both call it);
//! * the summation `sum()` actually performs, which changed in CPython 3.12 from
//!   naive left-to-right addition to Neumaier compensated summation. The caller
//!   passes which one its interpreter uses ([`Summation`]); the Python binding
//!   probes it at import time instead of trusting version numbers.
//!
//! Everything works on stack arrays: scanning a window allocates nothing.

/// Longest candidate either tier emits (`MAX_SPAN` in `detectors/entropy.py`).
pub const MAX_SPAN: usize = 8 * 1024;

/// Shortest candidate either regex accepts (`{20,MAX_SPAN}`).
const MIN_CANDIDATE: usize = 20;

/// The Python candidate regexes the scanners reproduce (for the spec check).
pub const ENTROPY_CANDIDATE_SRC: &str = "[A-Za-z0-9+/=_-]{20,8192}";
pub const COMPOUND_CANDIDATE_SRC: &str = r"[A-Za-z0-9+/=_\-!#$%^&*~]{20,8192}";

/// Strong password specials (`_STRONG_SPECIALS`).
const STRONG_SPECIALS: &[u8] = b"!#$%^&*~";

/// How CPython's `sum()` adds floats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Summation {
    /// Left-to-right `+=` (CPython <= 3.11).
    Naive,
    /// Neumaier compensated summation (CPython >= 3.12).
    Neumaier,
}

const fn class_table(extra: &[u8]) -> [bool; 256] {
    let mut t = [false; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        t[b] = c.is_ascii_alphanumeric();
        b += 1;
    }
    let mut i = 0;
    while i < extra.len() {
        t[extra[i] as usize] = true;
        i += 1;
    }
    t
}

/// `[A-Za-z0-9+/=_-]`
static ENTROPY_CLASS: [bool; 256] = class_table(b"+/=_-");
/// `[A-Za-z0-9+/=_\-!#$%^&*~]`
static COMPOUND_CLASS: [bool; 256] = class_table(b"+/=_-!#$%^&*~");

/// `re.finditer` of `[class]{20,MAX_SPAN}`: each maximal run of class bytes,
/// split greedily into consecutive spans of at most `MAX_SPAN`; a remainder
/// shorter than 20 is not a match. Byte offsets; class bytes are all ASCII, so
/// every span is ASCII and lies on character boundaries.
fn candidates(text: &[u8], class: &[bool; 256], mut emit: impl FnMut(usize, usize)) {
    let mut i = 0;
    while i < text.len() {
        if !class[text[i] as usize] {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && class[text[i] as usize] {
            i += 1;
        }
        let mut p = start;
        while i - p >= MIN_CANDIDATE {
            let e = (p + MAX_SPAN).min(i);
            emit(p, e);
            p = e;
        }
    }
}

/// CPython `sum()` over `terms`, which yields at least one term.
fn py_sum(terms: impl Iterator<Item = f64>, summation: Summation) -> f64 {
    // sum() starts from the int 0, so the first float becomes the total exactly.
    let mut terms = terms;
    let mut total = match terms.next() {
        Some(x) => 0.0 + x,
        None => return 0.0,
    };
    match summation {
        Summation::Naive => {
            for x in terms {
                total += x;
            }
            total
        }
        Summation::Neumaier => {
            // Objects/bltinmodule.c, builtin_sum_impl (CPython >= 3.12)
            let mut c = 0.0f64;
            for x in terms {
                let t = total + x;
                if total.abs() >= x.abs() {
                    c += (total - t) + x;
                } else {
                    c += (x - t) + total;
                }
                total = t;
            }
            if c != 0.0 && c.is_finite() {
                total += c;
            }
            total
        }
    }
}

/// Python `shannon_entropy` for an ASCII token, with no allocation.
fn entropy_ascii(token: &[u8], summation: Summation) -> f64 {
    let n = token.len();
    if n == 0 {
        return 0.0;
    }
    let mut counts = [0u32; 128];
    let mut order = [0u8; 128];
    let mut distinct = 0;
    for &b in token {
        let slot = &mut counts[b as usize];
        if *slot == 0 {
            order[distinct] = b;
            distinct += 1;
        }
        *slot += 1;
    }
    let nf = n as f64;
    let terms = order[..distinct].iter().map(|&b| {
        let p = counts[b as usize] as f64 / nf;
        p * p.log2()
    });
    -py_sum(terms, summation)
}

/// Python `shannon_entropy(text)` for any string: bits per character, terms in
/// first-occurrence order. ASCII input (every candidate) takes the
/// allocation-free path.
pub fn shannon_entropy(text: &str, summation: Summation) -> f64 {
    if text.is_ascii() {
        return entropy_ascii(text.as_bytes(), summation);
    }
    let mut counts: Vec<(char, u32)> = Vec::new();
    let mut n = 0usize;
    for ch in text.chars() {
        n += 1;
        match counts.iter_mut().find(|(c, _)| *c == ch) {
            Some((_, k)) => *k += 1,
            None => counts.push((ch, 1)),
        }
    }
    let nf = n as f64;
    let terms = counts.iter().map(|&(_, k)| {
        let p = k as f64 / nf;
        p * p.log2()
    });
    -py_sum(terms, summation)
}

/// `EntropyDetector` thresholds.
#[derive(Clone, Copy, Debug)]
pub struct EntropyParams {
    pub min_length: usize,
    pub base64_entropy: f64,
    pub hex_entropy: f64,
}

impl Default for EntropyParams {
    fn default() -> Self {
        Self {
            min_length: 24,
            base64_entropy: 4.0,
            hex_entropy: 3.0,
        }
    }
}

/// `EntropyDetector._secret_entropy`: the entropy if the token qualifies.
fn secret_entropy(token: &[u8], p: &EntropyParams, summation: Summation) -> Option<f64> {
    if token.len() < p.min_length {
        return None;
    }
    // a run of only letters is almost always prose/an identifier, not a secret
    if token.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let entropy = entropy_ascii(token, summation);
    if token.iter().all(u8::is_ascii_hexdigit) {
        return (token.len() >= 32 && entropy >= p.hex_entropy).then_some(entropy);
    }
    (entropy >= p.base64_entropy).then_some(entropy)
}

/// `EntropyDetector.detect`: emits `(byte_start, byte_end, entropy)`.
pub fn entropy_secrets(
    text: &str,
    params: &EntropyParams,
    summation: Summation,
    mut emit: impl FnMut(usize, usize, f64),
) {
    let bytes = text.as_bytes();
    candidates(bytes, &ENTROPY_CLASS, |s, e| {
        if let Some(h) = secret_entropy(&bytes[s..e], params, summation) {
            emit(s, e, h);
        }
    });
}

/// `CompoundSecretDetector` thresholds.
#[derive(Clone, Copy, Debug)]
pub struct CompoundParams {
    pub min_length: usize,
    pub entropy_floor: f64,
    pub distinct_ratio: f64,
}

impl Default for CompoundParams {
    fn default() -> Self {
        Self {
            min_length: 20,
            entropy_floor: 3.5,
            distinct_ratio: 0.45,
        }
    }
}

/// `CompoundSecretDetector._is_compound_secret`; the entropy if it qualifies.
fn compound_entropy(t: &[u8], p: &CompoundParams, summation: Summation) -> Option<f64> {
    let n = t.len();
    if n < p.min_length {
        return None;
    }
    // (1) a strong special sits between two alphanumerics
    let embedded = (1..n.saturating_sub(1)).any(|i| {
        STRONG_SPECIALS.contains(&t[i])
            && t[i - 1].is_ascii_alphanumeric()
            && t[i + 1].is_ascii_alphanumeric()
    });
    if !embedded {
        return None;
    }
    // (2) at least two of {lowercase, uppercase, digit}
    let classes = [
        t.iter().any(u8::is_ascii_lowercase),
        t.iter().any(u8::is_ascii_uppercase),
        t.iter().any(u8::is_ascii_digit),
    ];
    if classes.iter().filter(|&&x| x).count() < 2 {
        return None;
    }
    // (3) distinct-character ratio
    let mut seen = [false; 128];
    let mut distinct = 0usize;
    for &b in t {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    if (distinct as f64) / (n as f64) < p.distinct_ratio {
        return None;
    }
    // (4) entropy floor
    let entropy = entropy_ascii(t, summation);
    (entropy >= p.entropy_floor).then_some(entropy)
}

/// `CompoundSecretDetector.detect`: emits `(byte_start, byte_end, entropy)`.
pub fn compound_secrets(
    text: &str,
    params: &CompoundParams,
    summation: Summation,
    mut emit: impl FnMut(usize, usize, f64),
) {
    let bytes = text.as_bytes();
    // Prefilter (as in Python): no strong special anywhere, no candidate qualifies.
    if !bytes.iter().any(|b| STRONG_SPECIALS.contains(b)) {
        return;
    }
    candidates(bytes, &COMPOUND_CLASS, |s, e| {
        if let Some(h) = compound_entropy(&bytes[s..e], params, summation) {
            emit(s, e, h);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(text: &str) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        candidates(text.as_bytes(), &ENTROPY_CLASS, |s, e| v.push((s, e)));
        v
    }

    #[test]
    fn candidate_runs_split_at_max_span() {
        assert!(spans(&"a".repeat(19)).is_empty());
        assert_eq!(spans(&"a".repeat(20)), [(0, 20)]);
        let long = "a".repeat(MAX_SPAN + 25);
        assert_eq!(spans(&long), [(0, MAX_SPAN), (MAX_SPAN, MAX_SPAN + 25)]);
        // a remainder under 20 is dropped, as with re.finditer
        let long = "a".repeat(MAX_SPAN + 19);
        assert_eq!(spans(&long), [(0, MAX_SPAN)]);
        assert_eq!(spans("x y ab+/=_-cdefghijklmnopqr."), [(4, 27)]);
    }

    #[test]
    fn summation_modes_differ_where_python_versions_do() {
        // sum([1.0, 1e100, 1.0, -1e100]): 0.0 naive, 2.0 compensated
        let xs = [1.0, 1e100, 1.0, -1e100];
        assert_eq!(py_sum(xs.into_iter(), Summation::Naive), 0.0);
        assert_eq!(py_sum(xs.into_iter(), Summation::Neumaier), 2.0);
    }

    #[test]
    fn entropy_values() {
        for s in [Summation::Naive, Summation::Neumaier] {
            assert_eq!(shannon_entropy("", s), 0.0);
            assert_eq!(shannon_entropy("aaaa", s), 0.0);
            assert_eq!(shannon_entropy("abcd", s), 2.0);
            assert_eq!(shannon_entropy("文字文字", s), 1.0);
        }
    }

    #[test]
    fn entropy_tier_gates() {
        let p = EntropyParams::default();
        let s = Summation::Neumaier;
        let mut hits = Vec::new();
        // '=' is in the candidate class, so each run includes its key (as in Python)
        let text = "k=AbCdEfGh1234567890IjKlMnOpQr abcdefghijklmnopqrstuvwxyzab";
        entropy_secrets(text, &p, s, |a, b, _| hits.push(&text[a..b]));
        assert_eq!(hits, ["k=AbCdEfGh1234567890IjKlMnOpQr"]); // letters-only run rejected
    }

    #[test]
    fn compound_tier_gates() {
        let p = CompoundParams::default();
        let s = Summation::Neumaier;
        let mut hits = Vec::new();
        let text = "pw devPass_pP0p18yO3n!vT8wZ and aaaaaaaaaa!aaaaaaaaaa";
        compound_secrets(text, &p, s, |a, b, _| hits.push(&text[a..b]));
        assert_eq!(hits, ["devPass_pP0p18yO3n!vT8wZ"]);
        let mut none = 0;
        compound_secrets("no specials here at all", &p, s, |_, _, _| none += 1);
        assert_eq!(none, 0);
    }
}
