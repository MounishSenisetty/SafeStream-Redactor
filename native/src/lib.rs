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
use std::sync::OnceLock;

/// (entity_type, confidence, pattern source). The pattern strings must stay
/// byte-for-byte in sync with `detectors/deterministic.py`; the differential test
/// enforces equivalence, and `patterns()` (exposed to Python) lets the test read
/// them back for an exact-source check.
const PATTERNS: &[(&str, f64, &str)] = &[
    (
        "email",
        0.95,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
    (
        "private_key",
        0.99,
        r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY-----[A-Za-z0-9+/=\s]{1,8100}?-----END [A-Z0-9 ]{0,20}PRIVATE KEY-----",
    ),
    (
        "jwt",
        0.95,
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    ),
    ("aws_key", 0.98, r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    (
        "github_token",
        0.98,
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
    ),
    (
        "slack_token",
        0.98,
        r"\bxox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,3}\b",
    ),
    (
        "slack_webhook",
        0.98,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}",
    ),
    (
        "stripe_key",
        0.97,
        r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b",
    ),
    ("google_api_key", 0.95, r"\bAIza[0-9A-Za-z_-]{35}\b"),
    (
        "sendgrid_key",
        0.98,
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    ),
    ("twilio_key", 0.9, r"\bSK[0-9a-f]{32}\b"),
    ("npm_token", 0.98, r"\bnpm_[A-Za-z0-9]{36}\b"),
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
            .map(|(_, _, p)| Regex::new(p).expect("regex compiles"))
            .collect()
    })
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
            for m in re.find_iter(text) {
                out.push((m.start(), m.end(), idx));
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
            let (name, conf, _) = PATTERNS[idx];
            (cs, ce, name, conf)
        })
        .collect())
}

/// Expose the pattern table (type, confidence, source) so the differential test
/// can assert the sources match the Python tier exactly.
#[pyfunction]
fn patterns() -> Vec<(&'static str, f64, &'static str)> {
    PATTERNS.to_vec()
}

#[pymodule]
fn safestream_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(patterns, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
