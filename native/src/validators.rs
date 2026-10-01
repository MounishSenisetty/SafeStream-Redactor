//! Boundary checks and validators for the regex-lane PII patterns (ssn, ipv4,
//! ipv6). The candidates are the lookaround-free forms from
//! `detectors/_lookaround_free.py`; these functions reproduce the original
//! lookaround assertions and the Python validators exactly, reading the ORIGINAL
//! text with Python's character classes (`crate::unicode`).

use crate::unicode::{char_after, char_before, digit_value, is_digit, is_word};
use std::net::Ipv6Addr;

/// Reproduce SSN's `(?<![\d-])…(?![\d-])`: neither neighbour may be in `[\d-]`.
pub(crate) fn ssn_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let bad = |c: char| c == '-' || is_digit(c);
    !char_before(text, start).is_some_and(bad) && !char_after(text, end).is_some_and(bad)
}

/// Reproduce Python `ssn_ok` exactly. The candidate is `\d{3}-\d{2}-\d{4}`, so it
/// always splits into three parts on `-`. All checks are string comparisons (no
/// `int()`), so this is correct for Unicode-digit SSNs too — matching Python.
pub(crate) fn ssn_ok(m: &str) -> bool {
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

/// Value of a `\d{1,3}` octet as Python `int()` computes it (Unicode digits ok).
/// Returns `None` only if a char is not a decimal digit (never for a `\d` match).
fn octet_value(o: &str) -> Option<u32> {
    let mut val: u32 = 0;
    for c in o.chars() {
        val = val * 10 + digit_value(c)?;
    }
    Some(val)
}

/// Reproduce IPv4's `(?<![\d.])…(?!\d)(?!\.\d)`.
pub(crate) fn ipv4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let before = !char_before(text, start).is_some_and(|c| c == '.' || is_digit(c));
    let after = match char_after(text, end) {
        None => true,
        Some(c1) if is_digit(c1) => false, // (?!\d)
        // (?!\.\d): '.' followed by a digit is forbidden
        Some('.') => !text[end + 1..].chars().next().is_some_and(is_digit),
        Some(_) => true,
    };
    before && after
}

/// Reproduce Python `ipv4_ok`: each octet is "0", or has no ASCII leading zero
/// and a value <= 255. Uses Unicode-aware `int()` via `octet_value`.
pub(crate) fn ipv4_ok(m: &str) -> bool {
    m.split('.')
        .all(|o| o == "0" || (!o.starts_with('0') && octet_value(o).is_some_and(|v| v <= 255)))
}

/// Reproduce IPv6's `(?<![\w:.])…(?![\w:])`.
pub(crate) fn ipv6_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let before = !char_before(text, start).is_some_and(|c| c == ':' || c == '.' || is_word(c));
    let after = !char_after(text, end).is_some_and(|c| c == ':' || is_word(c));
    before && after
}

/// Reproduce Python `ipv6_ok`: `ipaddress.IPv6Address(m.split('%')[0])` parses.
/// The candidate contains no '%', so the split is a no-op; kept for exactness.
pub(crate) fn ipv6_ok(m: &str) -> bool {
    let head = m.split('%').next().unwrap_or(m);
    head.parse::<Ipv6Addr>().is_ok()
}
