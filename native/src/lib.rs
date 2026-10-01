//! Native detection core for SafeStream-Redactor — a byte-identical fast lane for
//! the deterministic tier, usable two ways:
//!
//! * **as a Rust library** (`rlib`, default features): `detect(text)` returns
//!   byte-offset [`Detection`]s, `detect_char_offsets(text)` the Python
//!   (character-offset) convention. No Python interpreter is linked.
//! * **as the `safestream_native` Python extension** (`--features python`, built
//!   by maturin): the thin PyO3 wrapper in `python.rs`, which the pure-Python
//!   `DeterministicDetector(backend="native"|"auto")` loads.
//!
//! Two lanes produce the detections:
//!
//! * **regex lane** — the lookaround-free patterns, each a separate `regex::Regex`
//!   scanned with `find_iter`. The crate's built-in required-literal prefilter
//!   (memchr/aho-corasick, SIMD) is the automatic analogue of the Python anchor
//!   prefilter. (A `RegexSet` was measured and rejected: the combined automaton is
//!   bloated by `private_key` and skips the per-pattern literal prefilter — ~6 MB/s
//!   vs 400–1200 MB/s; see `docs/NATIVE_CORE.md`.) The regex runs over a
//!   same-length *shadow* of the text whose characters carry Python's `\w`/`\d`/
//!   `\s` classes (`unicode.rs`), so `\b` and friends behave as in Python's `re`.
//! * **scanner lane** — `credit_card` and both `phone` patterns, whose
//!   lookahead-driven backtracking no DFA can express, as hand-rolled linear
//!   scanners (`structured.rs`).
//!
//! Correctness is gated by a differential test against the Python
//! `DeterministicDetector` (`tests/test_native_backend.py`); pure Python stays the
//! default and the oracle.

mod structured;
mod unicode;
mod unicode_tables;
mod validators;

#[cfg(feature = "python")]
mod python;

use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

pub use unicode::{digit_value, is_digit, is_space, is_word};
pub use unicode_tables::UNICODE_VERSION;

/// One detection. Offsets are **byte** offsets from [`detect`] and **character**
/// offsets from [`detect_char_offsets`]; `end` is exclusive in both.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Detection {
    pub start: usize,
    pub end: usize,
    /// The Python `EntityType` value, e.g. `"email"` or `"credit_card"`.
    pub entity_type: &'static str,
    pub confidence: f64,
}

/// One built-in pattern, as the Python spec defines it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PatternInfo {
    pub entity_type: &'static str,
    pub confidence: f64,
    /// The Python regex this pattern reproduces (for the lookaround-free regex
    /// lane, the candidate from `_lookaround_free.py`). The spec guard and the
    /// differential test compare these against the installed Python package.
    pub source: &'static str,
}

/// Post-match check for a regex-lane pattern. `Simple` patterns need none (the
/// regex is exact); the others reproduce the lookaround-free candidate's boundary
/// assertions + validator (`docs/NATIVE_CORE.md`).
#[derive(Clone, Copy, PartialEq)]
enum Check {
    Simple,
    Ssn,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Regex(Check),
    CreditCard,
    PhoneStructured,
    PhoneBare,
}

/// (entity_type, confidence, source, kind), in the order of `_PATTERNS` in
/// `detectors/deterministic.py` (which `resolve_overlaps` uses to break exact
/// ties). Regex-lane `Simple` sources match `deterministic.py` byte-for-byte; the
/// ssn/ipv4/ipv6 sources are the lookaround-free candidates; scanner sources are
/// the Python regexes the scanners reproduce.
const PATTERNS: &[(&str, f64, &str, Kind)] = &[
    (
        "email",
        0.95,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "private_key",
        0.99,
        r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY-----[A-Za-z0-9+/=\s]{1,8100}?-----END [A-Z0-9 ]{0,20}PRIVATE KEY-----",
        Kind::Regex(Check::Simple),
    ),
    (
        "jwt",
        0.95,
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "aws_key",
        0.98,
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "github_token",
        0.98,
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "slack_token",
        0.98,
        r"\bxox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,3}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "slack_webhook",
        0.98,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}",
        Kind::Regex(Check::Simple),
    ),
    (
        "stripe_key",
        0.97,
        r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "google_api_key",
        0.95,
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "sendgrid_key",
        0.98,
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "twilio_key",
        0.9,
        r"\bSK[0-9a-f]{32}\b",
        Kind::Regex(Check::Simple),
    ),
    (
        "npm_token",
        0.98,
        r"\bnpm_[A-Za-z0-9]{36}\b",
        Kind::Regex(Check::Simple),
    ),
    // Digit-gated PII (the real bottleneck on ordinary text).
    (
        "credit_card",
        0.9,
        structured::CREDIT_CARD_SRC,
        Kind::CreditCard,
    ),
    ("ssn", 0.85, r"\d{3}-\d{2}-\d{4}", Kind::Regex(Check::Ssn)),
    (
        "ipv4",
        0.9,
        r"\d{1,3}(?:\.\d{1,3}){3}",
        Kind::Regex(Check::Ipv4),
    ),
    // ipv6 candidate is ASCII hex + colons only, so it has no Unicode-digit case.
    (
        "ipv6",
        0.9,
        r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}",
        Kind::Regex(Check::Ipv6),
    ),
    (
        "phone",
        0.6,
        structured::PHONE_STRUCTURED_SRC,
        Kind::PhoneStructured,
    ),
    ("phone", 0.45, structured::PHONE_BARE_SRC, Kind::PhoneBare),
];

// One compiled `Regex` per regex-lane pattern (`None` for scanner patterns). We
// deliberately do NOT use `RegexSet` (see the module docs).
fn engine() -> &'static [Option<Regex>] {
    static ENGINE: OnceLock<Vec<Option<Regex>>> = OnceLock::new();
    ENGINE.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|&(_, _, src, kind)| match kind {
                Kind::Regex(_) => Some(Regex::new(src).expect("regex compiles")),
                _ => None,
            })
            .collect()
    })
}

/// The built-in patterns this core implements, in Python's `_PATTERNS` order.
pub fn patterns() -> impl Iterator<Item = PatternInfo> {
    PATTERNS
        .iter()
        .map(|&(entity_type, confidence, source, _)| PatternInfo {
            entity_type,
            confidence,
            source,
        })
}

/// Detect every match of the built-in patterns, with **byte** offsets.
///
/// Output equals the Python `DeterministicDetector` restricted to these patterns
/// (as a multiset; detections come grouped by pattern, in `patterns()` order, and
/// in text order within a pattern). Overlapping detections are all returned; the
/// caller arbitrates, as the Python pipeline does.
pub fn detect(text: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    // The regex lane reads the shadow (Python character classes); every
    // validator and boundary check reads the original text.
    let shadow: Cow<'_, str> = unicode::shadow(text);
    // Every credit_card/phone match contains a decimal digit; an ASCII text with
    // no ASCII digit cannot hold one (a non-ASCII text might, as a Unicode digit).
    let may_have_digit = !text.is_ascii() || text.bytes().any(|b| b.is_ascii_digit());
    for (idx, &(entity_type, confidence, _, kind)) in PATTERNS.iter().enumerate() {
        let mut push = |start: usize, end: usize| {
            out.push(Detection {
                start,
                end,
                entity_type,
                confidence,
            })
        };
        match kind {
            Kind::Regex(check) => {
                let re = engine()[idx].as_ref().expect("regex-lane pattern");
                for m in re.find_iter(&shadow) {
                    let (s, e) = (m.start(), m.end());
                    let accept = match check {
                        Check::Simple => true,
                        Check::Ssn => {
                            validators::ssn_boundary_ok(text, s, e)
                                && validators::ssn_ok(&text[s..e])
                        }
                        Check::Ipv4 => {
                            validators::ipv4_boundary_ok(text, s, e)
                                && validators::ipv4_ok(&text[s..e])
                        }
                        Check::Ipv6 => {
                            validators::ipv6_boundary_ok(text, s, e)
                                && validators::ipv6_ok(&text[s..e])
                        }
                    };
                    if accept {
                        push(s, e);
                    }
                }
            }
            _ if !may_have_digit => {}
            Kind::CreditCard => structured::credit_card(text, |s, e| {
                if structured::luhn_ok(&text[s..e]) {
                    push(s, e)
                }
            }),
            Kind::PhoneStructured => structured::phone_structured(text, |s, e| {
                if structured::phone_ok(&text[s..e]) {
                    push(s, e)
                }
            }),
            Kind::PhoneBare => structured::phone_bare(text, |s, e| {
                if structured::phone_ok(&text[s..e]) {
                    push(s, e)
                }
            }),
        }
    }
    out
}

/// [`detect`] with **character** offsets — the Python `Detection` convention.
pub fn detect_char_offsets(text: &str) -> Vec<Detection> {
    let mut dets = detect(text);
    to_char_offsets(text, &mut dets);
    dets
}

/// Rewrite byte offsets as character offsets in place.
///
/// ASCII fast path: when the text is all ASCII, byte offset == char offset and no
/// work is needed. Otherwise translate only the offsets actually used (two per
/// detection) in a single left-to-right pass over the text's char boundaries —
/// O(n + detections), with no per-character allocation.
fn to_char_offsets(text: &str, dets: &mut [Detection]) {
    if dets.is_empty() || text.is_ascii() {
        return;
    }
    let mut needed: Vec<usize> = dets.iter().flat_map(|d| [d.start, d.end]).collect();
    needed.sort_unstable();
    needed.dedup();
    let mut map = std::collections::HashMap::with_capacity(needed.len());
    let mut ni = 0usize;
    let mut ci = 0usize;
    for (bi, _) in text.char_indices() {
        if ni < needed.len() && needed[ni] == bi {
            map.insert(bi, ci);
            ni += 1;
        }
        ci += 1;
    }
    // any remaining needed offsets are end-of-text (== text.len())
    while ni < needed.len() {
        map.insert(needed[ni], ci);
        ni += 1;
    }
    for d in dets {
        d.start = map[&d.start];
        d.end = map[&d.end];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_regex_lane_pattern_compiles() {
        assert_eq!(engine().len(), PATTERNS.len());
    }

    #[test]
    fn byte_and_char_offsets() {
        let t = "文 bob@x.io";
        let b = detect(t);
        let c = detect_char_offsets(t);
        assert_eq!((b[0].start, b[0].end), (4, 12));
        assert_eq!((c[0].start, c[0].end), (2, 10));
        assert_eq!(&t[b[0].start..b[0].end], "bob@x.io");
    }

    #[test]
    fn python_word_boundaries_in_the_regex_lane() {
        // '²' is a Python word character, so there is no \b before "bob".
        assert!(detect("²bob@x.io").is_empty());
        // U+0301 (combining mark) is NOT a Python word character: \b holds.
        assert_eq!(detect("\u{301}bob@x.io").len(), 1);
        // Python \s includes \x1c, so it is valid inside a PEM body.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\x1cMIIE\n-----END RSA PRIVATE KEY-----";
        assert_eq!(detect(pem).len(), 1);
    }

    #[test]
    fn scanner_lane_is_wired() {
        let types: Vec<_> = detect("card 4111 1111 1111 1111 tel +1 (415) 555-2671")
            .into_iter()
            .map(|d| d.entity_type)
            .collect();
        assert!(types.contains(&"credit_card"));
        assert!(types.contains(&"phone"));
    }
}
