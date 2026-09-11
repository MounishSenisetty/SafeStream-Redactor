//! Native detection core for SafeStream-Redactor — optional, byte-identical fast lane.
//!
//! First slice (step 3 scaffold): the lookaround-free, group-0, no-validator,
//! no-case-fold credential patterns. These map straight onto Rust's `regex`
//! engine, whose `\b`/`\d`/`\w` are Unicode-aware and match Python's semantics —
//! the property that disqualified re2 (`docs/PERFORMANCE_BACKENDS.md`). Each
//! pattern is a separate `Regex` scanned with `find_iter`; the crate's built-in
//! required-literal prefilter (memchr/aho-corasick, SIMD) is the automatic
//! analogue of the Python anchor prefilter. (A `RegexSet` was measured and
//! rejected: the combined automaton is bloated by `private_key` and skips the
//! per-pattern literal prefilter — ~6 MB/s vs 400–1200 MB/s for individual
//! find_iter; see `docs/NATIVE_CORE.md`.) Output offsets are converted from Rust
//! **byte** offsets to Python **character** offsets so results are byte-identical
//! on non-ASCII input too.
//!
//! Correctness is not asserted here; it is gated by a differential test against
//! the Python `DeterministicDetector` (see `tests/`). This crate ships only behind
//! the optional `[native]` extra; pure Python stays the default and the oracle.

// PyO3 0.22's #[pyfunction] macro emits a benign `.into()` on the result type
// that clippy flags as a useless conversion; it lives in generated code, so the
// allow must be crate-level to reach it.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use regex::Regex;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

/// Post-match check applied to a candidate before it is accepted. `Simple`
/// patterns need none (the regex is exact). `Ssn` reproduces the lookaround-free
/// SSN's boundary assertions + validator (`docs/NATIVE_CORE.md`).
#[derive(Clone, Copy, PartialEq)]
enum Check {
    Simple,
    Ssn,
    Ipv4,
    Ipv6,
}

/// (entity_type, confidence, pattern source, check). Sources for `Simple`
/// patterns match `detectors/deterministic.py` byte-for-byte; the `Ssn` source is
/// the lookaround-free candidate from `detectors/_lookaround_free.py`. The
/// differential test enforces equivalence, and `patterns()` (exposed to Python)
/// lets the test read them back for an exact-source check.
const PATTERNS: &[(&str, f64, &str, Check)] = &[
    (
        "email",
        0.95,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        Check::Simple,
    ),
    (
        "private_key",
        0.99,
        r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY-----[A-Za-z0-9+/=\s]{1,8100}?-----END [A-Z0-9 ]{0,20}PRIVATE KEY-----",
        Check::Simple,
    ),
    (
        "jwt",
        0.95,
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        Check::Simple,
    ),
    (
        "aws_key",
        0.98,
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        Check::Simple,
    ),
    (
        "github_token",
        0.98,
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        Check::Simple,
    ),
    (
        "slack_token",
        0.98,
        r"\bxox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,3}\b",
        Check::Simple,
    ),
    (
        "slack_webhook",
        0.98,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}",
        Check::Simple,
    ),
    (
        "stripe_key",
        0.97,
        r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b",
        Check::Simple,
    ),
    (
        "google_api_key",
        0.95,
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        Check::Simple,
    ),
    (
        "sendgrid_key",
        0.98,
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        Check::Simple,
    ),
    ("twilio_key", 0.9, r"\bSK[0-9a-f]{32}\b", Check::Simple),
    ("npm_token", 0.98, r"\bnpm_[A-Za-z0-9]{36}\b", Check::Simple),
    // Digit-gated PII patterns (the real bottleneck): lookaround-free candidate +
    // Unicode-aware boundary check + validator. Byte-identical to Python including
    // Unicode-digit values (ssn via string ops; ipv4 via a full Unicode int()).
    ("ssn", 0.85, r"\d{3}-\d{2}-\d{4}", Check::Ssn),
    ("ipv4", 0.9, r"\d{1,3}(?:\.\d{1,3}){3}", Check::Ipv4),
    // ipv6 candidate is ASCII hex + colons only, so it has no Unicode-digit case.
    (
        "ipv6",
        0.9,
        r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}",
        Check::Ipv6,
    ),
];

// One compiled `Regex` per pattern. We deliberately do NOT use `RegexSet`: a
// combined automaton is bloated by the heavy `private_key` bound ({1,8100}) and,
// more importantly, does not use each pattern's required-literal prefilter — the
// bake-off measured RegexSet at ~6 MB/s vs individual find_iter at 400–1200 MB/s.
// Each individual `Regex` carries its own memchr/aho-corasick literal prefilter
// (SIMD), the automatic analogue of the Python anchor prefilter.
fn engine() -> &'static Vec<Regex> {
    static ENGINE: OnceLock<Vec<Regex>> = OnceLock::new();
    ENGINE.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|(_, _, p, _)| Regex::new(p).expect("regex compiles"))
            .collect()
    })
}

// --- boundary + validators for the digit-gated PII patterns ------------------
//
// The boundary character classes reproduce the ORIGINAL Python assertion classes
// with the same Unicode semantics: Python `\d` is Unicode-aware, so `[\d-]` must
// match Unicode digits too. Rust's `regex` uses Unicode `\d`, matching Python.
// The class regex is only run against the single characters adjacent to a match
// (rare), never over the whole input.

/// `[\d-]` — the SSN lookaround class (`(?<![\d-])` / `(?![\d-])`).
fn ssn_class() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"[\d-]").expect("class compiles"))
}

fn char_before(text: &str, start: usize) -> Option<char> {
    text[..start].chars().next_back()
}

fn char_after(text: &str, end: usize) -> Option<char> {
    text[end..].chars().next()
}

/// True if `c` is matched by the class regex (single-char test, no allocation).
fn in_class(cls: &Regex, c: char) -> bool {
    let mut buf = [0u8; 4];
    cls.is_match(c.encode_utf8(&mut buf))
}

/// Reproduce SSN's `(?<![\d-])…(?![\d-])`: neither neighbour may be in `[\d-]`.
fn ssn_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let cls = ssn_class();
    let before = char_before(text, start).is_none_or(|c| !in_class(cls, c));
    let after = char_after(text, end).is_none_or(|c| !in_class(cls, c));
    before && after
}

/// Reproduce Python `ssn_ok` exactly. The candidate is `\d{3}-\d{2}-\d{4}`, so it
/// always splits into three parts on `-`. All checks are string comparisons (no
/// `int()`), so this is correct for Unicode-digit SSNs too — matching Python.
fn ssn_ok(m: &str) -> bool {
    let mut it = m.split('-');
    let (area, group, serial) = match (it.next(), it.next(), it.next()) {
        (Some(a), Some(g), Some(s)) => (a, g, s),
        _ => return false, // unreachable for the candidate shape
    };
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    group != "00" && serial != "0000"
}

// --- Unicode decimal-digit value (Python int() parity) -----------------------
//
// Python's int() accepts ANY Unicode decimal digit (category Nd), so it detects
// Unicode-digit IPv4 like `٩٩.٩.٩.٩`. Rust's str::parse/char::to_digit are
// ASCII-only, so IPv4's octet-range validator would under-detect without this.
//
// Every Nd character is one of 66 contiguous 10-codepoint blocks: its value is
// `codepoint - block_zero`. DIGIT_BLOCK_ZEROS lists each block's '0'. The table
// is derived from the Unicode Character Database (Nd category); a Python-side
// test (`test_native_backend.py`) verifies native digit value == Python int() for
// EVERY Nd codepoint, so completeness is proven for the installed toolchains, not
// merely for a few sampled scripts.
const DIGIT_BLOCK_ZEROS: &[u32] = &[
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66, 0xDE6,
    0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50,
    0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0,
    0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0,
    0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16AC0, 0x16B50, 0x1D7CE,
    0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];

/// Decimal value 0-9 of a Unicode Nd digit, or `None` if `c` is not a decimal
/// digit — matching Python `int()` on a single character.
fn digit_value(c: char) -> Option<u32> {
    let cp = c as u32;
    if c.is_ascii_digit() {
        return Some(cp - 0x30);
    }
    match DIGIT_BLOCK_ZEROS.binary_search(&cp) {
        Ok(_) => Some(0), // c is a block's '0'
        Err(0) => None,   // below the first block
        Err(i) => {
            let zero = DIGIT_BLOCK_ZEROS[i - 1];
            if cp <= zero + 9 {
                Some(cp - zero)
            } else {
                None
            }
        }
    }
}

/// Value of a `\d{1,3}` octet as Python `int()` computes it (Unicode digits ok).
/// Returns `None` only if a char is not a decimal digit (never for a `\d` match).
fn octet_value(o: &str) -> Option<u32> {
    let mut val: u32 = 0;
    for c in o.chars() {
        val = val * 10 + digit_value(c)?;
    }
    Some(val)
}

fn class(re: &'static OnceLock<Regex>, src: &str) -> &'static Regex {
    re.get_or_init(|| Regex::new(src).expect("class compiles"))
}

/// Reproduce IPv4's `(?<![\d.])…(?!\d)(?!\.\d)` with Unicode `\d`.
fn ipv4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    static BEFORE: OnceLock<Regex> = OnceLock::new(); // [\d.]
    static DIGIT: OnceLock<Regex> = OnceLock::new(); // \d
    let before = char_before(text, start).is_none_or(|c| !in_class(class(&BEFORE, r"[\d.]"), c));
    let d = class(&DIGIT, r"\d");
    let after = match char_after(text, end) {
        None => true,
        Some(c1) if in_class(d, c1) => false, // (?!\d)
        Some('.') => {
            // (?!\.\d): '.' followed by a digit is forbidden
            let after_dot = text[end..].chars().nth(1);
            !after_dot.is_some_and(|c2| in_class(d, c2))
        }
        Some(_) => true,
    };
    before && after
}

/// Reproduce Python `ipv4_ok`: each octet is "0", or has no ASCII leading zero
/// and a value <= 255. Uses Unicode-aware `int()` via `octet_value`.
fn ipv4_ok(m: &str) -> bool {
    for o in m.split('.') {
        if o == "0" {
            continue;
        }
        // o[0] != "0" (ASCII zero) and int(o) <= 255
        if o.starts_with('0') {
            return false;
        }
        match octet_value(o) {
            Some(v) if v <= 255 => {}
            _ => return false,
        }
    }
    true
}

/// Reproduce IPv6's `(?<![\w:.])…(?![\w:])` with Unicode `\w`.
fn ipv6_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    static BEFORE: OnceLock<Regex> = OnceLock::new(); // [\w:.]
    static AFTER: OnceLock<Regex> = OnceLock::new(); // [\w:]
    let before = char_before(text, start).is_none_or(|c| !in_class(class(&BEFORE, r"[\w:.]"), c));
    let after = char_after(text, end).is_none_or(|c| !in_class(class(&AFTER, r"[\w:]"), c));
    before && after
}

/// Reproduce Python `ipv6_ok`: `ipaddress.IPv6Address(m.split('%')[0])` parses.
/// The candidate contains no '%', so the split is a no-op; kept for exactness.
fn ipv6_ok(m: &str) -> bool {
    let head = m.split('%').next().unwrap_or(m);
    head.parse::<Ipv6Addr>().is_ok()
}

/// Translate the byte offsets in `raw` (start, end, idx) to character offsets.
///
/// ASCII fast path: when the text is all ASCII, byte offset == char offset and no
/// work is needed. Otherwise translate only the offsets actually used (two per
/// match) in a single left-to-right pass over the text's char boundaries — O(n +
/// matches), with no giant per-call allocation.
fn to_char_offsets(text: &str, raw: &[(usize, usize, usize)]) -> Vec<(usize, usize, usize)> {
    if text.is_ascii() {
        return raw.to_vec();
    }
    let mut needed: Vec<usize> = raw.iter().flat_map(|&(s, e, _)| [s, e]).collect();
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
    raw.iter()
        .map(|&(s, e, idx)| (map[&s], map[&e], idx))
        .collect()
}

/// Detect all matches of the built-in credential patterns in `text`.
///
/// Returns a list of `(char_start, char_end, entity_type, confidence)`, matching
/// the offset convention of the Python `Detection` (character indices). Detection
/// order is unspecified; the caller sorts/arbitrates (as the Python pipeline does).
#[pyfunction]
fn detect(py: Python<'_>, text: &str) -> PyResult<Vec<(usize, usize, &'static str, f64)>> {
    // Release the GIL for the CPU-bound scan; no Python objects touched here.
    let raw: Vec<(usize, usize, usize)> = py.allow_threads(|| {
        let mut out: Vec<(usize, usize, usize)> = Vec::new();
        for (idx, re) in engine().iter().enumerate() {
            let check = PATTERNS[idx].3;
            for m in re.find_iter(text) {
                let (s, e) = (m.start(), m.end());
                let accept = match check {
                    Check::Simple => true,
                    Check::Ssn => ssn_boundary_ok(text, s, e) && ssn_ok(m.as_str()),
                    Check::Ipv4 => ipv4_boundary_ok(text, s, e) && ipv4_ok(m.as_str()),
                    Check::Ipv6 => ipv6_boundary_ok(text, s, e) && ipv6_ok(m.as_str()),
                };
                if accept {
                    out.push((s, e, idx));
                }
            }
        }
        out
    });

    if raw.is_empty() {
        return Ok(Vec::new());
    }
    Ok(to_char_offsets(text, &raw)
        .into_iter()
        .map(|(cs, ce, idx)| {
            let (name, conf, _, _) = PATTERNS[idx];
            (cs, ce, name, conf)
        })
        .collect())
}

/// Expose the pattern table (type, confidence, source) so the differential test
/// can assert the sources match the Python spec exactly.
#[pyfunction]
fn patterns() -> Vec<(&'static str, f64, &'static str)> {
    PATTERNS.iter().map(|&(n, c, s, _)| (n, c, s)).collect()
}

/// Test hook: the native decimal value of a single character (Python `int()`
/// parity check). Returns `None` for a non-digit or a multi-char string. Lets the
/// test prove the Unicode digit table is complete against Python's `int()`.
#[pyfunction]
fn digit_value_of(s: &str) -> Option<u32> {
    let mut it = s.chars();
    match (it.next(), it.next()) {
        (Some(c), None) => digit_value(c),
        _ => None,
    }
}

#[pymodule]
fn safestream_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(patterns, m)?)?;
    m.add_function(wrap_pyfunction!(digit_value_of, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
