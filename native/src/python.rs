//! PyO3 bindings (the default `python` feature): the `safestream_native` module.

// PyO3 0.22's #[pyfunction] macro emits a benign `.into()` on the result type
// that clippy flags as a useless conversion; it lives in generated code.
#![allow(clippy::useless_conversion)]

use crate::context::{Span, BOOST_TRIGGERS, SUPPRESS_TRIGGERS};
use crate::error::try_push;
use crate::secrets::{CompoundParams, EntropyParams, SecretMatch, Verdict};
use crate::{scan, scan_labeled, unicode, ByteMap, Error, LabeledMatch, OffsetMap, RawMatch, Scan};
use crate::{LABELED_RULES, PATTERNS};
use pyo3::exceptions::{PyMemoryError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::cell::RefCell;

fn to_py(err: Error) -> PyErr {
    match err {
        // Python's own out-of-memory signal: the CLI maps MemoryError to its
        // resource-exhaustion exit code (3) under --memory-limit.
        Error::OutOfMemory => PyMemoryError::new_err(err.to_string()),
        Error::Pattern { .. } => PyRuntimeError::new_err(err.to_string()),
    }
}

/// Per-thread scratch buffers, reused across calls so a scan does not allocate
/// once they have grown to the working size.
#[derive(Default)]
struct Scratch {
    raw: Vec<RawMatch>,
    labeled: Vec<LabeledMatch>,
    secrets: Vec<SecretMatch>,
    pairs: Vec<(usize, usize)>,
    spans: Vec<Span>,
    flags: Vec<u8>,
    lowered: Vec<u8>,
    offsets: OffsetMap,
    bytes: ByteMap,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

fn reserve<T>(n: usize) -> PyResult<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| to_py(Error::OutOfMemory))?;
    Ok(v)
}

type Detection = (usize, usize, &'static str, f64);
/// `(char_match_start, char_value_start, char_value_end, rule_index)`.
type Labeled = (usize, usize, usize, u8);

/// Scan `text` with the native patterns. Returns `(char_start, char_end,
/// entity_type, confidence)` tuples, or `None` when the text must be scanned by
/// the Python tier instead (a character the two engines classify differently;
/// see `unicode::needs_python`). The GIL is released for the scan.
#[pyfunction]
fn scan_text(py: Python<'_>, text: &str) -> PyResult<Option<Vec<Detection>>> {
    py.allow_threads(|| {
        SCRATCH.with(|cell| {
            let mut guard = cell.borrow_mut();
            let s = &mut *guard;
            if scan(text, &mut s.raw).map_err(to_py)? == Scan::NeedsPython {
                return Ok(None);
            }
            s.offsets
                .build(text, s.raw.iter().flat_map(|m| [m.start, m.end]))
                .map_err(to_py)?;
            let mut out = reserve(s.raw.len())?;
            for m in &s.raw {
                let spec = &PATTERNS[m.pattern as usize];
                out.push((
                    s.offsets.get(text, m.start),
                    s.offsets.get(text, m.end),
                    spec.name,
                    spec.confidence,
                ));
            }
            Ok(Some(out))
        })
    })
}

/// Scan `text` with the labeled-identifier rules. Returns `(char_match_start,
/// char_value_start, char_value_end, rule_index)`, or `None` to use Python.
#[pyfunction]
fn scan_labeled_text(py: Python<'_>, text: &str) -> PyResult<Option<Vec<Labeled>>> {
    py.allow_threads(|| {
        SCRATCH.with(|cell| {
            let mut guard = cell.borrow_mut();
            let s = &mut *guard;
            if scan_labeled(text, &mut s.labeled).map_err(to_py)? == Scan::NeedsPython {
                return Ok(None);
            }
            s.offsets
                .build(
                    text,
                    s.labeled
                        .iter()
                        .flat_map(|m| [m.start, m.value_start, m.value_end]),
                )
                .map_err(to_py)?;
            let mut out = reserve(s.labeled.len())?;
            for m in &s.labeled {
                out.push((
                    s.offsets.get(text, m.start),
                    s.offsets.get(text, m.value_start),
                    s.offsets.get(text, m.value_end),
                    m.rule,
                ));
            }
            Ok(Some(out))
        })
    })
}

/// `(char_start, char_end, entropy, decided)`; `decided` false means the caller
/// must classify (and format) this candidate itself.
type Secret = (usize, usize, f64, bool);

fn secrets_to_py(text: &str, s: &mut Scratch) -> PyResult<Vec<Secret>> {
    s.offsets
        .build(text, s.secrets.iter().flat_map(|m| [m.start, m.end]))
        .map_err(to_py)?;
    let mut out = reserve(s.secrets.len())?;
    for m in &s.secrets {
        out.push((
            s.offsets.get(text, m.start),
            s.offsets.get(text, m.end),
            m.entropy,
            m.verdict == Verdict::Secret,
        ));
    }
    Ok(out)
}

/// `EntropyDetector.detect`, natively: secret runs plus the rare runs whose
/// entropy is too close to a threshold (or a rounding boundary) to decide here.
#[pyfunction]
fn scan_entropy_text(
    py: Python<'_>,
    text: &str,
    min_length: usize,
    base64_entropy: f64,
    hex_entropy: f64,
) -> PyResult<Vec<Secret>> {
    let params = EntropyParams {
        min_length,
        base64_entropy,
        hex_entropy,
    };
    py.allow_threads(|| {
        SCRATCH.with(|cell| {
            let s = &mut *cell.borrow_mut();
            crate::scan_entropy(text, params, &mut s.secrets).map_err(to_py)?;
            secrets_to_py(text, s)
        })
    })
}

/// `CompoundSecretDetector.detect`, natively.
#[pyfunction]
fn scan_compound_text(
    py: Python<'_>,
    text: &str,
    min_length: usize,
    entropy_floor: f64,
    distinct_ratio: f64,
) -> PyResult<Vec<Secret>> {
    let params = CompoundParams {
        min_length,
        entropy_floor,
        distinct_ratio,
    };
    py.allow_threads(|| {
        SCRATCH.with(|cell| {
            let s = &mut *cell.borrow_mut();
            crate::scan_compound(text, params, &mut s.secrets).map_err(to_py)?;
            secrets_to_py(text, s)
        })
    })
}

/// `ContextualScorer.detect`: `(char_start, char_end)` of trigger-gated bare
/// SSNs, or `None` to use Python.
#[pyfunction]
fn scan_bare_ssn_text(
    py: Python<'_>,
    text: &str,
    window: usize,
) -> PyResult<Option<Vec<(usize, usize)>>> {
    py.allow_threads(|| {
        SCRATCH.with(|cell| {
            let s = &mut *cell.borrow_mut();
            if crate::scan_bare_ssn(text, window, &mut s.lowered, &mut s.pairs).map_err(to_py)?
                == Scan::NeedsPython
            {
                return Ok(None);
            }
            s.offsets
                .build(text, s.pairs.iter().flat_map(|&(a, b)| [a, b]))
                .map_err(to_py)?;
            let mut out = reserve(s.pairs.len())?;
            for &(a, b) in &s.pairs {
                out.push((s.offsets.get(text, a), s.offsets.get(text, b)));
            }
            Ok(Some(out))
        })
    })
}

/// `ContextualScorer.adjust` decisions: `spans` are `(char_start, char_end,
/// type_code)` (codes index `context_triggers()`); returns one byte per span
/// (bit 1 boost, bit 2 suppress), or `None` to use Python.
#[pyfunction]
fn adjust_text(
    py: Python<'_>,
    text: &str,
    spans: Vec<(usize, usize, u8)>,
    window: usize,
    suppress_window: usize,
) -> PyResult<Option<Py<PyBytes>>> {
    let flags = py.allow_threads(|| {
        SCRATCH.with(|cell| -> PyResult<Option<Vec<u8>>> {
            let s = &mut *cell.borrow_mut();
            // spans arrive in character offsets; the scan works in bytes
            s.bytes
                .build(text, spans.iter().flat_map(|&(a, b, _)| [a, b]))
                .map_err(to_py)?;
            s.spans.clear();
            for &(a, b, code) in &spans {
                let span = Span {
                    start: s.bytes.get(text, a),
                    end: s.bytes.get(text, b),
                    code,
                };
                if span.start > span.end {
                    return Ok(None); // not a span of this text: let Python decide
                }
                try_push(&mut s.spans, span).map_err(to_py)?;
            }
            let outcome = crate::adjust(
                text,
                &s.spans,
                window,
                suppress_window,
                &mut s.lowered,
                &mut s.flags,
            )
            .map_err(to_py)?;
            Ok((outcome == Scan::Exact).then(|| s.flags.clone()))
        })
    })?;
    Ok(flags.map(|f| PyBytes::new_bound(py, &f).unbind()))
}

/// The contextual trigger tables, for the spec guard: `([(type, triggers)],
/// suppress_triggers)`, boost codes being list indices.
#[pyfunction]
fn context_triggers() -> (Vec<(&'static str, Vec<&'static str>)>, Vec<&'static str>) {
    (
        BOOST_TRIGGERS
            .iter()
            .map(|&(t, words)| (t, words.to_vec()))
            .collect(),
        SUPPRESS_TRIGGERS.to_vec(),
    )
}

/// The E.164 country-code table `phone_ok` uses, for the spec guard.
#[pyfunction]
fn e164_country_codes() -> Vec<u16> {
    crate::digits::E164_COUNTRY_CODES.to_vec()
}

/// The pattern table `(entity_type, confidence, python_source)`, for the spec guard.
#[pyfunction]
fn patterns() -> Vec<(&'static str, f64, &'static str)> {
    PATTERNS
        .iter()
        .map(|p| (p.name, p.confidence, p.source))
        .collect()
}

/// The labeled-identifier rules `(python_source, entity_type, confidence)`.
#[pyfunction]
fn labeled_rules() -> Vec<(String, &'static str, f64)> {
    crate::rule_sources()
        .into_iter()
        .zip(LABELED_RULES)
        .map(|(src, &(_, _, ty, conf))| (src, ty, conf))
        .collect()
}

fn single_char(s: &str) -> Option<char> {
    let mut it = s.chars();
    match (it.next(), it.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    }
}

/// Test hook: the native decimal value of one character (Python `int()` parity).
#[pyfunction]
fn digit_value_of(s: &str) -> Option<u32> {
    single_char(s).and_then(unicode::digit_value)
}

/// Test hook: `(is_word, is_digit, ambiguous_word, ambiguous_digit,
/// ambiguous_space, ambiguous_fold)` for one character, so a test can prove that
/// on every unambiguous code point the native classes equal CPython's.
#[pyfunction]
fn classify(s: &str) -> Option<(bool, bool, bool, bool, bool, bool)> {
    let c = single_char(s)?;
    let (w, d, sp, f) = unicode::ambiguity(c);
    Some((unicode::is_word(c), unicode::is_digit(c), w, d, sp, f))
}

/// Test hook: whether `text` would be handed back to the Python tier.
#[pyfunction]
fn needs_python(text: &str) -> bool {
    unicode::needs_python(text)
}

#[pymodule]
fn safestream_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // compile every pattern at import: a defect surfaces as an ImportError-time
    // RuntimeError (and the Python side falls back), never mid-redaction
    crate::warm_up().map_err(to_py)?;
    m.add_function(wrap_pyfunction!(scan_text, m)?)?;
    m.add_function(wrap_pyfunction!(scan_labeled_text, m)?)?;
    m.add_function(wrap_pyfunction!(scan_entropy_text, m)?)?;
    m.add_function(wrap_pyfunction!(scan_compound_text, m)?)?;
    m.add_function(wrap_pyfunction!(scan_bare_ssn_text, m)?)?;
    m.add_function(wrap_pyfunction!(adjust_text, m)?)?;
    m.add_function(wrap_pyfunction!(context_triggers, m)?)?;
    m.add_function(wrap_pyfunction!(e164_country_codes, m)?)?;
    m.add_function(wrap_pyfunction!(patterns, m)?)?;
    m.add_function(wrap_pyfunction!(labeled_rules, m)?)?;
    m.add_function(wrap_pyfunction!(digit_value_of, m)?)?;
    m.add_function(wrap_pyfunction!(classify, m)?)?;
    m.add_function(wrap_pyfunction!(needs_python, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
