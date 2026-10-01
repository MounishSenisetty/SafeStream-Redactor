//! Native detection core for SafeStream-Redactor — an optional, byte-identical
//! fast lane for the Python tier.
//!
//! The crate is usable two ways:
//!
//! * as the `safestream_native` Python extension (the default `python` feature,
//!   built by maturin), and
//! * as a plain Rust library with `--no-default-features`: no PyO3, no GIL, no
//!   Python objects in the dependency graph.
//!
//! Every scanner is meant to be byte-identical to the Python tier
//! (`detectors/deterministic.py`, `detectors/labeled_id.py`): same spans, same
//! types. Where Rust's `regex` and CPython's `re` classify a character
//! differently, [`scan`] reports [`Scan::NeedsPython`] instead of guessing (see
//! [`unicode::needs_python`]). Correctness is gated by differential tests against
//! the Python implementation (`tests/test_native_backend.py`) and by the property
//! tests in `tests/`.
//!
//! Offsets in the Rust API are **byte** offsets; the Python bindings convert them
//! to character offsets ([`OffsetMap`]).

// No production path may panic: failures are `Error`s the bindings turn into
// Python exceptions. Enforced by clippy (tests may unwrap).
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

/// Synthetic corpora for the benchmarks and property tests (not a stable API).
#[doc(hidden)]
pub mod corpus;
mod digits;
pub mod error;
mod labeled;
mod offsets;
pub mod patterns;
pub mod unicode;
mod unicode_tables;

#[cfg(feature = "python")]
mod python;

pub use error::Error;
pub use labeled::{rule_sources, LabeledMatch, RULES as LABELED_RULES};
pub use offsets::OffsetMap;
pub use patterns::{Kind, PatternSpec, PATTERNS};

/// One match from [`scan`]: byte offsets into the scanned text, and the index of
/// its pattern in [`PATTERNS`] (which gives the entity type and confidence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawMatch {
    pub start: usize,
    pub end: usize,
    pub pattern: u16,
}

/// Whether a scan's output is authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scan {
    /// The matches are exactly what the Python tier finds.
    Exact,
    /// The text contains a character the two engines classify differently in a
    /// position where it could change a match; the output buffer is empty and the
    /// text must be scanned by the Python tier.
    NeedsPython,
}

// Evaluated at compile time only (it initialises a `const`), so its panic is a
// build error, never a runtime one.
#[allow(clippy::panic)]
const fn slot(kind: Kind) -> u16 {
    let mut i = 0;
    while i < PATTERNS.len() {
        if PATTERNS[i].kind as u8 == kind as u8 {
            return i as u16;
        }
        i += 1;
    }
    panic!("scanner pattern missing from PATTERNS") // compile-time only (const)
}

const SLOTS: digits::Slots = digits::Slots {
    card: slot(Kind::CreditCard),
    phone_structured: slot(Kind::PhoneStructured),
    phone_bare: slot(Kind::PhoneBare),
};

/// Scan `text` with every pattern in [`PATTERNS`], replacing the contents of
/// `out`. Reuse `out` across calls: once it has grown, a scan allocates nothing.
/// Order: the regex patterns in table order (each by position), then the
/// card/phone scanners' matches by position. Callers sort as needed.
pub fn scan(text: &str, out: &mut Vec<RawMatch>) -> Result<Scan, Error> {
    out.clear();
    if unicode::needs_python(text) {
        return Ok(Scan::NeedsPython);
    }
    patterns::scan_regex(text, out)?;
    digits::scan_digits(text, SLOTS, out)?;
    Ok(Scan::Exact)
}

/// Scan `text` with the label-anchored identifier rules ([`LABELED_RULES`]),
/// replacing the contents of `out`.
pub fn scan_labeled(text: &str, out: &mut Vec<LabeledMatch>) -> Result<Scan, Error> {
    out.clear();
    if unicode::needs_python(text) {
        return Ok(Scan::NeedsPython);
    }
    labeled::scan_labeled(text, out)?;
    Ok(Scan::Exact)
}

/// Benchmark hooks: one scanner family at a time (not a stable API).
#[doc(hidden)]
pub mod bench_hooks {
    use super::*;

    pub fn regex_only(text: &str, out: &mut Vec<RawMatch>) -> Result<(), Error> {
        out.clear();
        patterns::scan_regex(text, out)
    }

    pub fn digits_only(text: &str, out: &mut Vec<RawMatch>) -> Result<(), Error> {
        out.clear();
        digits::scan_digits(text, SLOTS, out)
    }

    pub fn needs_python(text: &str) -> bool {
        unicode::needs_python(text)
    }
}

/// Compile every pattern up front instead of on the first scan.
pub fn warm_up() -> Result<(), Error> {
    patterns::warm_up()?;
    labeled::warm_up()
}
