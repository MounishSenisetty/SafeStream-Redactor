//! `safestream_native` — the PyO3 binding over the pure-Rust core. Built only
//! with `--features python` (maturin passes it, see `pyproject.toml`); it adds no
//! detection logic of its own.

// PyO3 0.22's #[pyfunction] macro emits a benign `.into()` on the result type
// that clippy flags as a useless conversion; it lives in generated code, so the
// allow must cover the whole module to reach it.
#![allow(clippy::useless_conversion)]

use crate::{CharCursor, CompoundParams, EntropyParams, Summation};
use pyo3::prelude::*;

/// Detect all matches of the built-in patterns in `text`.
///
/// Returns a list of `(char_start, char_end, entity_type, confidence)`, matching
/// the offset convention of the Python `Detection` (character indices). The
/// caller sorts/arbitrates, as the Python pipeline does.
#[pyfunction]
fn detect(py: Python<'_>, text: &str) -> PyResult<Vec<(usize, usize, &'static str, f64)>> {
    // Release the GIL for the CPU-bound scan; no Python objects touched here.
    let dets = py.allow_threads(|| crate::detect_char_offsets(text));
    Ok(dets
        .into_iter()
        .map(|d| (d.start, d.end, d.entity_type, d.confidence))
        .collect())
}

/// Expose the pattern table (type, confidence, source) so the spec guard and the
/// differential test can assert the sources match the Python spec exactly.
#[pyfunction]
fn patterns() -> Vec<(&'static str, f64, &'static str)> {
    crate::patterns()
        .map(|p| (p.entity_type, p.confidence, p.source))
        .collect()
}

/// Test hook: the native decimal value of a single character (Python `int()`
/// parity check). Returns `None` for a non-digit or a multi-char string. Lets the
/// test prove the Unicode digit table is complete against Python's `int()`.
#[pyfunction]
fn digit_value_of(s: &str) -> Option<u32> {
    single_char(s).and_then(crate::digit_value)
}

/// Test hook: the native `(\w, \d, \s)` membership of a single character, so the
/// test can compare it with Python's `re` for every codepoint.
#[pyfunction]
fn char_classes_of(s: &str) -> Option<(bool, bool, bool)> {
    single_char(s).map(|c| (crate::is_word(c), crate::is_digit(c), crate::is_space(c)))
}

fn summation(neumaier: bool) -> Summation {
    if neumaier {
        Summation::Neumaier
    } else {
        Summation::Naive
    }
}

/// Byte spans from an entropy scanner, as `(char_start, char_end, entropy)`.
fn char_spans(
    text: &str,
    scan: impl FnOnce(&mut dyn FnMut(usize, usize, f64)),
) -> Vec<(usize, usize, f64)> {
    let mut spans = Vec::new();
    scan(&mut |s, e, h| spans.push((s, e, h)));
    if !text.is_ascii() {
        let mut cursor = CharCursor::new(text);
        for (s, e, _) in &mut spans {
            *s = cursor.char_index(*s);
            *e = cursor.char_index(*e);
        }
    }
    spans
}

/// `EntropyDetector.detect` candidates that qualify, as
/// `(char_start, char_end, entropy)`. `neumaier` says whether this interpreter's
/// `sum()` uses compensated summation (probed by the caller).
#[pyfunction]
fn entropy_secrets(
    py: Python<'_>,
    text: &str,
    min_length: usize,
    base64_entropy: f64,
    hex_entropy: f64,
    neumaier: bool,
) -> Vec<(usize, usize, f64)> {
    let params = EntropyParams {
        min_length,
        base64_entropy,
        hex_entropy,
    };
    py.allow_threads(|| {
        char_spans(text, |emit| {
            crate::entropy_secrets(text, &params, summation(neumaier), emit)
        })
    })
}

/// `CompoundSecretDetector.detect` candidates that qualify, as
/// `(char_start, char_end, entropy)`.
#[pyfunction]
fn compound_secrets(
    py: Python<'_>,
    text: &str,
    min_length: usize,
    entropy_floor: f64,
    distinct_ratio: f64,
    neumaier: bool,
) -> Vec<(usize, usize, f64)> {
    let params = CompoundParams {
        min_length,
        entropy_floor,
        distinct_ratio,
    };
    py.allow_threads(|| {
        char_spans(text, |emit| {
            crate::compound_secrets(text, &params, summation(neumaier), emit)
        })
    })
}

/// Test hook: Python `shannon_entropy(text)` computed natively.
#[pyfunction]
fn shannon_entropy(text: &str, neumaier: bool) -> f64 {
    crate::shannon_entropy(text, summation(neumaier))
}

fn single_char(s: &str) -> Option<char> {
    let mut it = s.chars();
    match (it.next(), it.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    }
}

#[pymodule]
fn safestream_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(patterns, m)?)?;
    m.add_function(wrap_pyfunction!(digit_value_of, m)?)?;
    m.add_function(wrap_pyfunction!(char_classes_of, m)?)?;
    m.add_function(wrap_pyfunction!(entropy_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(compound_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add("ENTROPY_MAX_SPAN", crate::ENTROPY_MAX_SPAN)?;
    m.add("ENTROPY_CANDIDATE_SRC", crate::ENTROPY_CANDIDATE_SRC)?;
    m.add("COMPOUND_CANDIDATE_SRC", crate::COMPOUND_CANDIDATE_SRC)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("UNICODE_VERSION", crate::UNICODE_VERSION)?;
    Ok(())
}
