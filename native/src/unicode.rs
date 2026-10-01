//! Character classes with CPython `re` semantics, and the ambiguity check that
//! keeps the native core byte-identical to the Python tier.
//!
//! Rust's `regex` and CPython's `re` are both Unicode-aware but classify some
//! characters differently (see `tools/gen_unicode_tables.py`). For every code
//! point outside the generated `*_AMBIGUOUS` tables the two agree on every
//! supported interpreter, so the predicates here (and the compiled patterns) are
//! exact for them. [`needs_python`] reports when an ambiguous code point sits
//! where it could change a match; the caller then scans that text with Python.

use crate::unicode_tables::{DIGIT_AMBIGUOUS, FOLD_AMBIGUOUS, SPACE_AMBIGUOUS, WORD_AMBIGUOUS};

// Every Nd character is one of 76 contiguous 10-codepoint blocks (Unicode 16.0,
// the version of Python 3.14 and of the regex crate's `\d`): its value is
// `codepoint - block_zero`. DIGIT_BLOCK_ZEROS lists each block's '0'. A
// Python-side test (`test_native_backend.py`) verifies digit_value == int() for
// EVERY Nd codepoint, and a Rust test that it agrees with the regex crate's `\d`.
const DIGIT_BLOCK_ZEROS: &[u32] = &[
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0, 0x11C50, 0x11D50,
    0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8,
    0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
];

/// Decimal value 0-9 of a Unicode Nd digit, or `None` if `c` is not a decimal
/// digit — matching Python `int()` on a single character.
#[inline]
pub fn digit_value(c: char) -> Option<u32> {
    let cp = c as u32;
    if c.is_ascii() {
        return c.is_ascii_digit().then(|| cp - 0x30);
    }
    match DIGIT_BLOCK_ZEROS.binary_search(&cp) {
        Ok(_) => Some(0), // c is a block's '0'
        Err(0) => None,   // below the first block
        Err(i) => {
            let zero = DIGIT_BLOCK_ZEROS[i - 1];
            (cp <= zero + 9).then(|| cp - zero)
        }
    }
}

/// `\d`: a Unicode decimal digit (category Nd).
#[inline]
pub fn is_digit(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        digit_value(c).is_some()
    }
}

/// `\w`: the compiled patterns' word class, which equals CPython's
/// (`str.isalnum()` or `_`) on every code point outside `WORD_AMBIGUOUS`.
#[inline]
pub fn is_word(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        regex_syntax::is_word_character(c)
    }
}

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Which classifications of `c` differ between Rust and some supported CPython:
/// `(word, digit, space, case_fold)`. Exposed for the exhaustive parity test.
pub fn ambiguity(c: char) -> (bool, bool, bool, bool) {
    (
        in_table(WORD_AMBIGUOUS, c),
        in_table(DIGIT_AMBIGUOUS, c),
        in_table(SPACE_AMBIGUOUS, c),
        in_table(FOLD_AMBIGUOUS, c),
    )
}

/// A character that a pattern can consume right next to a word-boundary test:
/// ASCII punctuation/letters/digits, any decimal digit, and the two non-ASCII
/// characters that case-insensitively match an ASCII letter (`ſ` ~ `s`, the
/// Kelvin sign ~ `k`).
#[inline]
fn boundary_anchor(c: char) -> bool {
    c.is_ascii_graphic() || is_digit(c) || c == '\u{17F}' || c == '\u{212A}'
}

/// True when the two engines could disagree on `text`, so it must be scanned by
/// the Python oracle instead.
///
/// * A digit-, whitespace- or case-fold-ambiguous code point anywhere: it can be
///   consumed *inside* a match (`\d`, `\s`, `(?i)` letters).
/// * A word-ambiguous code point next to a [`boundary_anchor`]. `\w` is only ever
///   used in assertions (`\b`, boundary checks), and every such test compares a
///   character the pattern consumes — always a boundary anchor — with its
///   neighbour. A word-ambiguous character elsewhere (inside Devanagari or Thai
///   text, say) cannot reach any assertion, so it does not force the fallback.
///
/// All-ASCII text is never ambiguous (the four ASCII separators Python counts as
/// whitespace are added to the compiled `\s` explicitly).
pub fn needs_python(text: &str) -> bool {
    if text.is_ascii() {
        return false;
    }
    let mut prev: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if !c.is_ascii() {
            let (word, digit, space, fold) = ambiguity(c);
            if digit || space || fold {
                return true;
            }
            if word
                && (prev.is_some_and(boundary_anchor)
                    || chars.peek().copied().is_some_and(boundary_anchor))
            {
                return true;
            }
        }
        prev = Some(c);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_table_agrees_with_regex_d() {
        let re = regex::Regex::new(r"\A\d\z").unwrap();
        let mut buf = [0u8; 4];
        for cp in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            assert_eq!(
                is_digit(c),
                re.is_match(c.encode_utf8(&mut buf)),
                "U+{cp:04X}"
            );
        }
    }

    #[test]
    fn word_predicate_agrees_with_regex_w() {
        let re = regex::Regex::new(r"\A\w\z").unwrap();
        let mut buf = [0u8; 4];
        for cp in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            assert_eq!(
                is_word(c),
                re.is_match(c.encode_utf8(&mut buf)),
                "U+{cp:04X}"
            );
        }
    }

    #[test]
    fn ambiguity_rules() {
        assert!(!needs_python("plain ascii key=AKIAIOSFODNN7EXAMPLE"));
        assert!(!needs_python("文字 naïve café ٩٩.٩.٩.٩"));
        // combining acute right after a key, ZWJ after an email
        assert!(needs_python("AKIAIOSFODNN7EXAMPLE\u{301}"));
        assert!(needs_python("a@b.io\u{200D}"));
        // a combining mark inside Devanagari text, away from anything a pattern
        // consumes, does not force the fallback
        assert!(!needs_python("नमस्ते दुनिया"));
        // dotted capital I folds to `i` in Python only
        assert!(needs_python("SİN 123"));
    }
}
