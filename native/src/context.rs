//! The contextual tier (`detectors/contextual.py`): trigger-gated bare SSNs, and
//! the confidence `adjust` pass that boosts or suppresses every detection by the
//! words around it.
//!
//! Python matches trigger words against `str.lower()` of a context window. All
//! triggers are ASCII, so only characters that lower-case *to* ASCII matter. On
//! every supported CPython there are exactly two non-ASCII ones (checked by
//! `test_native_backend.py`): the Kelvin sign (-> `k`, mapped here) and `İ`
//! (-> `i` + combining dot, handed to Python: the caller checks
//! [`needs_python_lower`]). Everything else lower-cases to non-ASCII and is
//! mapped to a byte no trigger contains, so matching needs no allocation and no
//! Unicode case tables.

use crate::error::{try_push, Error};
use crate::unicode::is_digit;

/// `contextual._BOOST_TRIGGERS`, indexed by the type code the caller passes
/// (0 = a type with no boost triggers).
pub const BOOST_TRIGGERS: &[(&str, &[&str])] = &[
    ("", &[]),
    ("ssn", &["ssn", "social security", "social-security"]),
    ("phone", &["phone", "tel", "mobile", "cell", "fax", "call"]),
    (
        "credit_card",
        &["card", "visa", "mastercard", "amex", "cc", "payment"],
    ),
    ("email", &["email", "e-mail", "mail", "contact"]),
    (
        "api_key",
        &["key", "secret", "token", "password", "credential", "auth"],
    ),
    ("ipv4", &["ip", "host", "server", "addr"]),
    ("ipv6", &["ip", "host", "server", "addr"]),
];

/// `contextual._SUPPRESS_TRIGGERS`.
pub const SUPPRESS_TRIGGERS: &[&str] = &[
    "example",
    "sample",
    "dummy",
    "test",
    "fake",
    "placeholder",
    "lorem",
    "xxx-xx",
];

/// Bit flags returned by [`adjust`].
pub const BOOSTED: u8 = 1;
pub const SUPPRESSED: u8 = 2;

/// True when Python's `str.lower()` would produce ASCII the mapping below does
/// not reproduce: the text contains `İ` (U+0130).
pub fn needs_python_lower(text: &str) -> bool {
    text.contains('\u{130}')
}

/// One character of `str.lower()` as far as ASCII triggers can tell.
#[inline]
fn lower_byte(c: char) -> u8 {
    if c.is_ascii() {
        c.to_ascii_lowercase() as u8
    } else if c == '\u{212A}' {
        b'k' // KELVIN SIGN lower-cases to ASCII 'k'
    } else {
        0xFF // lower-cases to non-ASCII: matches no trigger
    }
}

/// Map `s` into `buf` (cleared first).
fn lower_into(s: &str, buf: &mut Vec<u8>) -> Result<(), Error> {
    buf.clear();
    for c in s.chars() {
        try_push(buf, lower_byte(c))?;
    }
    Ok(())
}

#[inline]
fn contains(hay: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    n.len() <= hay.len() && hay.windows(n.len()).any(|w| w == n)
}

/// The byte offset `chars` characters before byte offset `at` (clamped at 0).
#[inline]
fn back(text: &str, at: usize, chars: usize) -> usize {
    text[..at]
        .char_indices()
        .rev()
        .nth(chars.saturating_sub(1))
        .map_or(0, |(b, _)| if chars == 0 { at } else { b })
}

/// `contextual._word_in`: a suppress trigger lies whole inside `text[lo..hi]` and
/// is a word of the full text (neither neighbour, in or out of the range, is
/// `[a-z0-9_]` once lower-cased). `lower_into` maps one char to one byte, so
/// `scratch` indices are character indices.
fn word_in(text: &str, lo: usize, hi: usize, scratch: &mut Vec<u8>) -> Result<bool, Error> {
    let a = back(text, lo, 1);
    let b = text[hi..].chars().next().map_or(hi, |c| hi + c.len_utf8());
    lower_into(&text[a..b], scratch)?;
    let first = usize::from(a < lo);
    let limit = scratch.len() - usize::from(b > hi);
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    Ok(SUPPRESS_TRIGGERS.iter().any(|t| {
        let n = t.len();
        limit >= first + n
            && (first..=limit - n).any(|i| {
                scratch[i..i + n] == *t.as_bytes()
                    && (i == 0 || !word(scratch[i - 1]))
                    && (i + n == scratch.len() || !word(scratch[i + n]))
            })
    }))
}

/// `ContextualScorer.detect`: a maximal run of exactly nine digits with neither
/// neighbour `-`, i.e. `(?<![\d-])\d{9}(?![\d-])`, preceded within `window`
/// characters by an SSN trigger. Byte offsets.
pub(crate) fn scan_bare_ssn(
    text: &str,
    window: usize,
    scratch: &mut Vec<u8>,
    out: &mut Vec<(usize, usize)>,
) -> Result<(), Error> {
    let mut prev: Option<char> = None;
    let mut iter = text.char_indices().peekable();
    while let Some((start, c)) = iter.next() {
        if !is_digit(c) || prev.is_some_and(|p| p == '-' || is_digit(p)) {
            prev = Some(c);
            continue;
        }
        // a digit run starting at `start`
        let mut count = 1;
        let mut end = start + c.len_utf8();
        let mut last = c;
        while let Some(&(b, d)) = iter.peek() {
            if !is_digit(d) {
                break;
            }
            count += 1;
            end = b + d.len_utf8();
            last = d;
            iter.next();
        }
        let after_ok = !iter.peek().is_some_and(|&(_, d)| d == '-');
        if count == 9 && after_ok {
            lower_into(&text[back(text, start, window)..start], scratch)?;
            if BOOST_TRIGGERS[1].1.iter().any(|t| contains(scratch, t)) {
                try_push(out, (start, end))?;
            }
        }
        prev = Some(last);
    }
    Ok(())
}

/// One detection for [`adjust`]: byte offsets and its boost-trigger type code.
#[derive(Clone, Copy, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub code: u8,
}

/// `ContextualScorer.adjust`'s two decisions for each span, as [`BOOSTED`] /
/// [`SUPPRESSED`] bits; the caller applies the confidence arithmetic (in Python,
/// so the floats are Python's own).
pub(crate) fn adjust(
    text: &str,
    spans: &[Span],
    window: usize,
    suppress_window: usize,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    out.clear();
    for s in spans {
        let mut flags = 0u8;
        let triggers = BOOST_TRIGGERS
            .get(usize::from(s.code))
            .map_or(&[][..], |t| t.1);
        if !triggers.is_empty() {
            lower_into(&text[back(text, s.start, window)..s.start], scratch)?;
            if triggers.iter().any(|t| contains(scratch, t)) {
                flags |= BOOSTED;
            }
        }
        // the near window and the match itself: two separate ranges
        let near = back(text, s.start, suppress_window);
        if word_in(text, near, s.start, scratch)? || word_in(text, s.start, s.end, scratch)? {
            flags |= SUPPRESSED;
        }
        try_push(out, flags)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn back_counts_characters() {
        let t = "ab文字cd";
        let at = t.find('c').unwrap();
        assert_eq!(&t[back(t, at, 2)..at], "文字");
        assert_eq!(&t[back(t, at, 99)..at], "ab文字");
        assert_eq!(back(t, at, 0), at);
    }

    #[test]
    fn suppress_triggers_are_whole_words_of_the_full_text() {
        let mut s = Vec::new();
        let hit = |t: &str, lo: usize, hi: usize, s: &mut Vec<u8>| word_in(t, lo, hi, s).unwrap();
        assert!(hit("a TEST b", 0, 8, &mut s));
        assert!(hit("x@EXAMPLE.com", 0, 13, &mut s));
        assert!(!hit("latest", 0, 6, &mut s));
        assert!(!hit("sk_test_abc", 0, 11, &mut s));
        // the range cuts "latest" to "test": the neighbour outside still counts
        assert!(!hit("latest", 2, 6, &mut s));
        // a trigger straddling the range end is not inside it
        assert!(!hit("test", 0, 3, &mut s));
        assert!(hit("test", 0, 4, &mut s));
    }

    #[test]
    fn bare_ssn_needs_a_trigger_and_exactly_nine_digits() {
        let mut scratch = Vec::new();
        let mut out = Vec::new();
        let t = "SSN: 123456789 and 1234567890 and ssn 12345678-9 x 987654321 and far away from any trigger word at all: 555443333";
        scan_bare_ssn(t, 48, &mut scratch, &mut out).unwrap();
        // 987654321 is within 48 characters of the earlier "ssn" (as in Python);
        // 555443333 is not; 10-digit and '-'-adjacent runs never qualify
        assert_eq!(
            out.iter().map(|&(s, e)| &t[s..e]).collect::<Vec<_>>(),
            ["123456789", "987654321"]
        );
    }
}
