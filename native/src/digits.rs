//! Linear-time scanners for `credit_card` and the two `phone` patterns.
//!
//! These patterns cannot be a plain DFA: each has a greedy, variable-length core
//! over an alphabet that includes its own separators, guarded by a negative
//! lookahead, and Python's backtracking falls back to a *shorter* match when the
//! lookahead fails at the greedy end. A candidate regex + post-filter cannot
//! reproduce that (`docs/NATIVE_CORE.md`), and a backtracking engine
//! (`fancy-regex`) was built, measured and rejected (truncation under its
//! backtrack limit, no speedup).
//!
//! So each pattern is matched here by a direct transcription of the regex,
//! exploring alternatives in exactly CPython's priority order (greedy quantifiers
//! longest-first, `?` take-first, alternation left-first). Two properties keep it
//! linear with no backtracking blow-up:
//!
//! * a match is bounded (card <= 37 chars, phone <= 36), so all work for one start
//!   position happens inside a fixed, stack-allocated window of `WIN` chars;
//! * the repetition search is memoised on `(position, iteration)`, so each state
//!   is solved once per start (at most `WIN x 5` states).
//!
//! Start positions are visited left to right and each pattern resumes after its
//! own last match, as `re.finditer` does. Validators (`luhn_ok`, `phone_ok`) run
//! after the match, never feeding back into the search, again as in Python.

use crate::error::{try_push, Error};
use crate::unicode::{digit_value, is_digit, is_word};
use crate::RawMatch;

/// Window size in characters: the longest match plus the two characters the
/// trailing lookaheads read, with margin.
const WIN: usize = 48;

/// Indices of the scanner patterns in `patterns::PATTERNS`.
#[derive(Clone, Copy)]
pub(crate) struct Slots {
    pub card: u16,
    pub phone_structured: u16,
    pub phone_bare: u16,
}

/// Up to `WIN` characters starting at a candidate, with their byte offsets
/// relative to the start (at most `WIN * 4 = 192`, so a `u8` holds them).
/// Filling stops one character after the first one no pattern here can consume,
/// so typical windows are a handful of characters long.
struct Window {
    ch: [char; WIN],
    off: [u8; WIN + 1],
    len: usize,
}

#[inline]
fn consumable(c: char) -> bool {
    matches!(c, '0'..='9' | ' ' | '.' | '-' | '(' | ')' | '+') || (!c.is_ascii() && is_digit(c))
}

impl Window {
    #[inline]
    fn fill(text: &str, start: usize) -> Window {
        let mut w = Window {
            ch: ['\0'; WIN],
            off: [0; WIN + 1],
            len: 0,
        };
        let rest = &text[start..];
        let mut rel = 0usize;
        while w.len < WIN && rel < rest.len() {
            let b = rest.as_bytes()[rel];
            let c = if b < 0x80 {
                b as char
            } else {
                match rest[rel..].chars().next() {
                    Some(c) => c,
                    None => break,
                }
            };
            w.ch[w.len] = c;
            w.off[w.len] = rel as u8;
            w.len += 1;
            rel += c.len_utf8();
            if !consumable(c) {
                break;
            }
        }
        w.off[w.len] = rel as u8;
        w
    }

    /// Absolute byte offset of window index `i` (`i <= len`).
    #[inline]
    fn byte(&self, start: usize, i: usize) -> usize {
        start + self.off[i] as usize
    }

    /// Character `i` of the window; `None` past the end of the text. (A window
    /// cut at `WIN` is never read that far: matches end before index 38.)
    #[inline]
    fn at(&self, i: usize) -> Option<char> {
        (i < self.len).then(|| self.ch[i])
    }

    #[inline]
    fn digit(&self, i: usize) -> bool {
        self.at(i).is_some_and(is_digit)
    }

    /// Length of the digit run starting at `i`, capped at `cap`.
    #[inline]
    fn run(&self, i: usize, cap: usize) -> usize {
        let mut n = 0;
        while n < cap && self.digit(i + n) {
            n += 1;
        }
        n
    }
}

#[inline]
fn is_phone_sep(c: Option<char>) -> bool {
    matches!(c, Some(' ' | '.' | '-'))
}

/// `(?![\w-])(?!\.\d)` at window index `i`.
#[inline]
fn phone_tail_ok(w: &Window, i: usize) -> bool {
    match w.at(i) {
        None => true,
        Some('.') => !w.digit(i + 1),
        Some(c) => !(c == '-' || is_word(c)),
    }
}

// --- credit_card: (?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-]) -------------------
//
// From a start digit the units `\d[ -]?` must chain digit to digit with at most
// one separator between them; skipping an available separator can never lead to
// a match (the next token needs a digit), so a match ending at the j-th digit of
// the chain is unique. Greedy `{12,18}` tries j = 18 down to 12, and the first j
// whose following character satisfies `(?![\d-])` is CPython's match.

fn match_card(w: &Window) -> Option<usize> {
    if w.len < 13 {
        return None; // 13 digits minimum, and the window stops at the first non-digit run
    }
    let mut pos = [0usize; 19]; // window index of each digit in the chain
    let mut n = 0;
    let mut i = 0;
    while n < 19 {
        pos[n] = i;
        n += 1;
        if w.digit(i + 1) {
            i += 1;
        } else if matches!(w.at(i + 1), Some(' ' | '-')) && w.digit(i + 2) {
            i += 2;
        } else {
            break;
        }
    }
    (12..n)
        .rev()
        .map(|j| pos[j] + 1)
        .find(|&end| !w.at(end).is_some_and(|c| c == '-' || is_digit(c)))
}

/// Python `luhn_ok` over the digits of the matched span.
fn luhn_ok(w: &Window, end: usize) -> bool {
    let mut total = 0u32;
    let mut count = 0u32;
    for &c in w.ch[..end].iter().rev() {
        if let Some(mut d) = digit_value(c) {
            if count % 2 == 1 {
                d *= 2;
                if d > 9 {
                    d -= 9;
                }
            }
            total += d;
            count += 1;
        }
    }
    (13..=19).contains(&count) && total % 10 == 0
}

// --- phone (structured) -----------------------------------------------------
// (?<![\w.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{1,4}\)[ .-]?)
//     \d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-])(?!\.\d)

/// Memo for `(?:[ .-]?\d{2,4}){min,4}` + tail: 0 = unknown, 1 = no match,
/// `end + 2` = matches ending at window index `end`.
struct Memo([u8; WIN * 5]);

impl Memo {
    fn new() -> Memo {
        Memo([0; WIN * 5])
    }
}

/// The `{1,4}` repetition with optional separator (structured phone), entered
/// after `count` iterations at window index `i`. Greedy: one more iteration first
/// (separator taken first, then 4/3/2 digits), then stop if the tail holds.
fn rep_structured(w: &Window, memo: &mut Memo, i: usize, count: usize) -> Option<usize> {
    if i >= WIN {
        return None;
    }
    let key = i * 5 + count;
    match memo.0[key] {
        0 => {}
        1 => return None,
        v => return Some(v as usize - 2),
    }
    let mut found = None;
    if count < 4 {
        let starts: [Option<usize>; 2] = [is_phone_sep(w.at(i)).then_some(i + 1), Some(i)];
        'outer: for d in starts.into_iter().flatten() {
            for k in (2..=w.run(d, 4)).rev() {
                if let Some(end) = rep_structured(w, memo, d + k, count + 1) {
                    found = Some(end);
                    break 'outer;
                }
            }
        }
    }
    if found.is_none() && count >= 1 && phone_tail_ok(w, i) {
        found = Some(i);
    }
    memo.0[key] = found.map_or(1, |e| e as u8 + 2);
    found
}

/// `\d{2,4}` then the repetition, from window index `i`.
fn core_structured(w: &Window, memo: &mut Memo, i: usize) -> Option<usize> {
    (2..=w.run(i, 4))
        .rev()
        .find_map(|k| rep_structured(w, memo, i + k, 0))
}

/// `[ .-]?` (taken first) followed by `next`.
fn opt_sep(w: &Window, i: usize, mut next: impl FnMut(usize) -> Option<usize>) -> Option<usize> {
    if is_phone_sep(w.at(i)) {
        if let Some(end) = next(i + 1) {
            return Some(end);
        }
    }
    next(i)
}

/// `\(\d{1,4}\)` at `i`, then `next` after the `)`; digits greedy 4..1.
fn paren_group(
    w: &Window,
    i: usize,
    mut next: impl FnMut(usize) -> Option<usize>,
) -> Option<usize> {
    if w.at(i) != Some('(') {
        return None;
    }
    (1..=w.run(i + 1, 4))
        .rev()
        .filter(|&k| w.at(i + 1 + k) == Some(')'))
        .find_map(|k| next(i + 2 + k))
}

fn match_phone_structured(w: &Window) -> Option<usize> {
    let mut memo = Memo::new();
    match w.at(0) {
        // \+ \d{1,3} [ .-]? (?:\(\d{1,4}\)[ .-]?)?  core
        Some('+') => (1..=w.run(1, 3)).rev().find_map(|n| {
            opt_sep(w, 1 + n, |p| {
                paren_group(w, p, |q| {
                    opt_sep(w, q, |r| core_structured(w, &mut memo, r))
                })
                .or_else(|| core_structured(w, &mut memo, p))
            })
        }),
        // \(\d{1,4}\) [ .-]?  core
        Some('(') => paren_group(w, 0, |q| {
            opt_sep(w, q, |r| core_structured(w, &mut memo, r))
        }),
        _ => None,
    }
}

// --- phone (bare): (?<![\w.+(-])\d{2,4}(?:[ .-]\d{2,4}){2,4}(?![\w-])(?!\.\d)

fn rep_bare(w: &Window, memo: &mut Memo, i: usize, count: usize) -> Option<usize> {
    if i >= WIN {
        return None;
    }
    let key = i * 5 + count;
    match memo.0[key] {
        0 => {}
        1 => return None,
        v => return Some(v as usize - 2),
    }
    let mut found = None;
    if count < 4 && is_phone_sep(w.at(i)) {
        found = (2..=w.run(i + 1, 4))
            .rev()
            .find_map(|k| rep_bare(w, memo, i + 1 + k, count + 1));
    }
    if found.is_none() && count >= 2 && phone_tail_ok(w, i) {
        found = Some(i);
    }
    memo.0[key] = found.map_or(1, |e| e as u8 + 2);
    found
}

fn match_phone_bare(w: &Window) -> Option<usize> {
    // needs 2-4 digits then a separator before any repetition can start
    let run = w.run(0, 4);
    if run < 2 || !(2..=run).any(|k| is_phone_sep(w.at(k))) {
        return None;
    }
    let mut memo = Memo::new();
    (2..=w.run(0, 4))
        .rev()
        .find_map(|k| rep_bare(w, &mut memo, k, 0))
}

/// Python `phone_ok` on the matched window span `[0, end)`.
fn phone_ok(w: &Window, end: usize) -> bool {
    let span = &w.ch[..end];
    let shape = |groups: &[usize]| -> bool {
        // digits in `groups` separated by single '-', nothing else
        let mut i = 0;
        for (g, &len) in groups.iter().enumerate() {
            if g > 0 {
                if span.get(i) != Some(&'-') {
                    return false;
                }
                i += 1;
            }
            if !span
                .get(i..i + len)
                .is_some_and(|s| s.iter().all(|&c| is_digit(c)))
            {
                return false;
            }
            i += len;
        }
        i == span.len()
    };
    // _DATE_SHAPE: (?:19|20)\d{2}-\d{2}-\d{2} ; _SSN_SHAPE: \d{3}-\d{2}-\d{4}
    let date = matches!(span, ['1', '9', ..] | ['2', '0', ..]) && shape(&[4, 2, 2]);
    if date || shape(&[3, 2, 4]) {
        return false;
    }
    let digits = span.iter().filter(|&&c| is_digit(c)).count();
    (7..=15).contains(&digits)
}

/// ASCII bytes that can start a match: a digit, `+` or `(`.
#[inline]
fn ascii_candidate(b: u8) -> bool {
    b.is_ascii_digit() || b == b'+' || b == b'('
}

const ONES: u64 = 0x0101_0101_0101_0101;
const HIGHS: u64 = 0x8080_8080_8080_8080;

/// Some byte of `x` lies strictly between `m` and `n` (all bytes < 0x80;
/// `m`, `n` <= 128). Hacker's Delight `hasbetween`, branch-free over 8 bytes.
#[inline]
fn has_between(x: u64, m: u64, n: u64) -> bool {
    let t = x & (ONES * 127);
    ((ONES * (127 + n)).wrapping_sub(t) & !x & t.wrapping_add(ONES * (127 - m)) & HIGHS) != 0
}

/// Eight bytes, any of which might start a match or begin a non-ASCII char: a
/// digit (0x30-0x39), 0x28-0x2B (a superset of `(` and `+`), or a high bit.
/// A superset is fine: the byte loop re-checks exactly.
#[inline]
fn word_may_start(x: u64) -> bool {
    x & HIGHS != 0 || has_between(x, 0x2F, 0x3A) || has_between(x, 0x27, 0x2C)
}

/// Advance `at` past bytes that cannot start a match: 8 at a time (SWAR), then
/// byte by byte. Returns the new position (== `bytes.len()` if none is left).
#[inline]
fn skip_to_candidate(bytes: &[u8], mut at: usize) -> usize {
    while let Some(chunk) = bytes.get(at..at + 8) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        if word_may_start(u64::from_le_bytes(word)) {
            break;
        }
        at += 8;
    }
    while at < bytes.len() && bytes[at] < 0x80 && !ascii_candidate(bytes[at]) {
        at += 1;
    }
    at
}

/// Append every credit_card / phone match in `text` (byte offsets) to `out`.
pub(crate) fn scan_digits(text: &str, slots: Slots, out: &mut Vec<RawMatch>) -> Result<(), Error> {
    let bytes = text.as_bytes();
    // per-pattern resume points: finditer never starts inside its previous match
    let (mut card_from, mut sphone_from, mut bphone_from) = (0usize, 0usize, 0usize);
    let mut prev: Option<char> = None;
    let mut at = 0usize;
    while at < bytes.len() {
        // skip ASCII that cannot start a match (the common case), 8 bytes at a time
        let skip_from = at;
        at = skip_to_candidate(bytes, at);
        if at > skip_from {
            prev = Some(bytes[at - 1] as char);
            if at == bytes.len() {
                break;
            }
        }
        let b = bytes[at];
        let c = if b < 0x80 {
            b as char
        } else {
            match text[at..].chars().next() {
                Some(c) => c,
                None => break,
            }
        };
        let digit = is_digit(c);
        if digit || c == '+' || c == '(' {
            let prev_word = prev.is_some_and(is_word);
            let card_start =
                digit && at >= card_from && !prev.is_some_and(|p| p == '-' || is_digit(p));
            let sphone_start =
                !digit && at >= sphone_from && !(prev_word || matches!(prev, Some('.' | '-')));
            let bphone_start = digit
                && at >= bphone_from
                && !(prev_word || matches!(prev, Some('.' | '+' | '(' | '-')));
            if card_start || sphone_start || bphone_start {
                let w = Window::fill(text, at);
                if card_start {
                    if let Some(end) = match_card(&w) {
                        card_from = w.byte(at, end);
                        if luhn_ok(&w, end) {
                            let m = RawMatch {
                                start: at,
                                end: card_from,
                                pattern: slots.card,
                            };
                            try_push(out, m)?;
                        }
                    }
                }
                if sphone_start {
                    if let Some(end) = match_phone_structured(&w) {
                        sphone_from = w.byte(at, end);
                        if phone_ok(&w, end) {
                            let m = RawMatch {
                                start: at,
                                end: sphone_from,
                                pattern: slots.phone_structured,
                            };
                            try_push(out, m)?;
                        }
                    }
                }
                if bphone_start {
                    if let Some(end) = match_phone_bare(&w) {
                        bphone_from = w.byte(at, end);
                        if phone_ok(&w, end) {
                            let m = RawMatch {
                                start: at,
                                end: bphone_from,
                                pattern: slots.phone_bare,
                            };
                            try_push(out, m)?;
                        }
                    }
                }
            }
        }
        prev = Some(c);
        at += c.len_utf8();
        if digit {
            // the rest of an ASCII digit run cannot start anything: each of its
            // digits follows a digit (no card / bare phone) and is not `+`/`(`
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                prev = Some(bytes[at] as char);
                at += 1;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swar_prefilter_never_misses_a_candidate() {
        // every byte value at every lane: a candidate (or non-ASCII) byte must
        // make word_may_start true
        for lane in 0..8 {
            for b in 0u8..=255 {
                let mut word = [b'x'; 8];
                word[lane] = b;
                let must = b >= 0x80 || ascii_candidate(b);
                if must {
                    assert!(
                        word_may_start(u64::from_le_bytes(word)),
                        "byte {b:#x} lane {lane}"
                    );
                }
            }
        }
        assert!(!word_may_start(u64::from_le_bytes(*b"abc xyz!")));
    }
}
