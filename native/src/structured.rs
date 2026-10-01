//! Linear-time scanners for `credit_card` and the two `phone` patterns.
//!
//! These patterns cannot use the regex lane: their greedy, separator-bearing
//! cores are followed by negative lookaheads, and when a lookahead fails Python's
//! backtracking engine retreats to a *shorter* match. A lookaround-free candidate
//! plus post-filter cannot recover that shorter match, and `fancy-regex` was built
//! and rejected (truncation and catastrophic backtracking; `docs/NATIVE_CORE.md`).
//!
//! Each scanner below reproduces `re.finditer` for its exact Python pattern: the
//! same start positions, the same depth-first order over quantifier choices
//! (greedy = longest first, optional = present first), the same lookarounds with
//! Python's character classes. Work per start position is bounded by a constant
//! (credit_card: 19 digits; phone: memoised over `(position, group count)`), so a
//! scan is linear in the input with no backtracking blow-up on dense digits.
//! `tests/test_native_backend.py` gates every scanner against Python `re`,
//! including a character-level fuzz over digits, separators and Unicode
//! neighbours.

use crate::unicode::{char_after, char_before, digit_value, is_digit, is_space, is_word};

/// UTF-8 length of the character whose first byte is `b`.
#[inline]
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// `re.finditer` driver: try a match at every character boundary, left to right;
/// after a match, resume at its end (matches never overlap). `may_start` rejects
/// ASCII bytes that cannot begin a match without decoding; non-ASCII characters
/// are always tried (a Unicode digit can begin a digit-led match).
fn find_iter(
    text: &str,
    may_start: impl Fn(u8) -> bool,
    mut try_at: impl FnMut(usize) -> Option<usize>,
    mut emit: impl FnMut(usize, usize),
) {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let b = bytes[pos];
        if b < 0x80 && !may_start(b) {
            pos += 1;
            continue;
        }
        match try_at(pos) {
            Some(end) => {
                emit(pos, end);
                pos = end;
            }
            None => pos += utf8_len(b),
        }
    }
}

/// Byte ends of up to `max` (<= 4) consecutive Python `\d` characters at `pos`.
struct DigitRun {
    ends: [usize; 4],
    len: usize,
}

fn digit_run(text: &str, pos: usize, max: usize) -> DigitRun {
    let mut run = DigitRun {
        ends: [0; 4],
        len: 0,
    };
    let mut i = pos;
    for c in text[pos..].chars() {
        if run.len == max || !is_digit(c) {
            break;
        }
        i += c.len_utf8();
        run.ends[run.len] = i;
        run.len += 1;
    }
    run
}

/// Greedy `\d{lo,hi}` alternatives, longest first: the byte end after each count.
fn digit_choices(text: &str, pos: usize, lo: usize, hi: usize) -> impl Iterator<Item = usize> {
    let run = digit_run(text, pos, hi);
    (lo..=run.len).rev().map(move |n| run.ends[n - 1])
}

// --- credit_card -------------------------------------------------------------
//
// Python: (?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])
//
// Reading a candidate as a chain of digits, each optionally followed by ONE
// separator: the optional `[ -]?` is always taken when present (skipping it puts
// a separator where the next `\d` must be, which fails), so the only real choice
// is the number of digits t in 13..=19. Greedy-then-backtrack tries t from
// min(19, chain length) down to 13 and keeps the first whose next character
// passes `(?![\d-])`.

pub(crate) const CREDIT_CARD_SRC: &str = r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])";

fn credit_card_at(text: &str, p: usize) -> Option<usize> {
    let first = char_after(text, p)?;
    if !is_digit(first) {
        return None;
    }
    if char_before(text, p).is_some_and(|c| c == '-' || is_digit(c)) {
        return None;
    }
    let mut ends = [0usize; 19];
    let mut n = 0;
    let mut cur = p;
    let mut c = first;
    loop {
        let end = cur + c.len_utf8();
        ends[n] = end;
        n += 1;
        if n == 19 {
            break;
        }
        let next = match char_after(text, end) {
            Some(' ' | '-') => end + 1,
            _ => end,
        };
        match char_after(text, next) {
            Some(d) if is_digit(d) => {
                cur = next;
                c = d;
            }
            _ => break,
        }
    }
    (13..=n)
        .rev()
        .map(|t| ends[t - 1])
        .find(|&e| !char_after(text, e).is_some_and(|c| c == '-' || is_digit(c)))
}

/// Python `luhn_ok`: 13-19 digits (Unicode digits by value) passing Luhn.
pub(crate) fn luhn_ok(m: &str) -> bool {
    // Walk the digits right to left, counting and summing in one pass.
    let mut count = 0usize;
    let mut total = 0u32;
    for d in m.chars().rev().filter_map(digit_value) {
        total += if count % 2 == 1 {
            let d2 = d * 2;
            if d2 > 9 {
                d2 - 9
            } else {
                d2
            }
        } else {
            d
        };
        count += 1;
    }
    (13..=19).contains(&count) && total.is_multiple_of(10)
}

/// Raw `finditer` matches of the credit_card pattern (before `luhn_ok`).
pub(crate) fn credit_card(text: &str, emit: impl FnMut(usize, usize)) {
    find_iter(
        text,
        |b| b.is_ascii_digit(),
        |p| credit_card_at(text, p),
        emit,
    );
}

// --- phone (shared pieces) ---------------------------------------------------

/// `[ .-]?` alternatives at `pos`, greedy: the separator first when present.
fn optional_sep(text: &str, pos: usize) -> impl Iterator<Item = usize> {
    let has = matches!(char_after(text, pos), Some(' ' | '.' | '-'));
    [has.then_some(pos + 1), Some(pos)].into_iter().flatten()
}

/// The phone patterns' trailing `(?![\w-])(?!\.\d)`.
fn phone_tail_ok(text: &str, pos: usize) -> bool {
    match char_after(text, pos) {
        None => true,
        Some(c) if c == '-' || is_word(c) => false,
        Some('.') => !text[pos + 1..].chars().next().is_some_and(is_digit),
        Some(_) => true,
    }
}

// --- phone, structured -------------------------------------------------------
//
// Python:
//   (?<![\w.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{1,4}\)[ .-]?)
//   \d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-])(?!\.\d)
//
// The body's optional separators let a digit run split many ways, so the
// depth-first search is memoised on (position, groups so far): whether the rest
// of the pattern matches from a state does not depend on how it was reached.
// That keeps the work per start bounded by states x choices, not by paths.

pub(crate) const PHONE_STRUCTURED_SRC: &str = concat!(
    r"(?<![\w.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{1,4}\)[ .-]?)",
    r"\d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-])(?!\.\d)"
);

/// Bytes a structured-phone match can extend past its start: 36 characters
/// (prefix `+ddd (dddd) ` is 12, body `dddd` + 4 x ` dddd` is 24), each at
/// most 4 bytes in UTF-8. Every state the search visits lies inside that span.
const MEMO_SPAN: usize = 36 * 4 + 1;

/// Fixed-size memo for one start position, on the stack. Entries are valid only
/// for the current `stamp`, so moving to the next start is O(1) (no clearing).
/// Each slot holds `(stamp, end - base + 1)`, with 0 meaning "no match".
struct Memo {
    base: usize,
    stamp: u32,
    slots: [[(u32, u32); 5]; MEMO_SPAN],
}

impl Memo {
    fn new() -> Self {
        Memo {
            base: 0,
            stamp: 0,
            slots: [[(0, 0); 5]; MEMO_SPAN],
        }
    }

    fn reset(&mut self, base: usize) {
        if self.stamp == u32::MAX {
            self.slots = [[(0, 0); 5]; MEMO_SPAN];
            self.stamp = 0;
        }
        self.stamp += 1;
        self.base = base;
    }

    fn slot(&self, pos: usize, count: u8) -> Option<(u32, u32)> {
        let row = self.slots.get(pos.checked_sub(self.base)?)?;
        row.get(count as usize).copied()
    }

    fn get(&self, pos: usize, count: u8) -> Option<Option<usize>> {
        let (stamp, v) = self.slot(pos, count)?;
        (stamp == self.stamp).then(|| v.checked_sub(1).map(|r| self.base + r as usize))
    }

    fn put(&mut self, pos: usize, count: u8, found: Option<usize>) {
        let (base, stamp) = (self.base, self.stamp);
        let Some(off) = pos.checked_sub(base) else {
            return;
        };
        if let Some(slot) = self
            .slots
            .get_mut(off)
            .and_then(|r| r.get_mut(count as usize))
        {
            *slot = (stamp, found.map_or(0, |e| (e - base + 1) as u32));
        }
    }
}

/// `(?:[ .-]?\d{2,4}){count..=4}` (needing at least one group) then the tail.
fn structured_groups(text: &str, pos: usize, count: u8, memo: &mut Memo) -> Option<usize> {
    if let Some(known) = memo.get(pos, count) {
        return known;
    }
    let mut found = None;
    if count < 4 {
        'search: for s in optional_sep(text, pos) {
            for end in digit_choices(text, s, 2, 4) {
                if let Some(e) = structured_groups(text, end, count + 1, memo) {
                    found = Some(e);
                    break 'search;
                }
            }
        }
    }
    if found.is_none() && count >= 1 && phone_tail_ok(text, pos) {
        found = Some(pos);
    }
    memo.put(pos, count, found);
    found
}

/// `\d{2,4}(?:[ .-]?\d{2,4}){1,4}` + tail, from `pos`.
fn structured_body(text: &str, pos: usize, memo: &mut Memo) -> Option<usize> {
    digit_choices(text, pos, 2, 4).find_map(|end| structured_groups(text, end, 0, memo))
}

/// `\(\d{1,4}\)[ .-]?` followed by the body, from `pos` (which holds the `(`).
fn paren_then_body(text: &str, pos: usize, memo: &mut Memo) -> Option<usize> {
    if char_after(text, pos) != Some('(') {
        return None;
    }
    for end in digit_choices(text, pos + 1, 1, 4) {
        if char_after(text, end) == Some(')') {
            for s in optional_sep(text, end + 1) {
                if let Some(e) = structured_body(text, s, memo) {
                    return Some(e);
                }
            }
        }
    }
    None
}

fn phone_structured_at(text: &str, p: usize, memo: &mut Memo) -> Option<usize> {
    let first = char_after(text, p)?;
    if first != '+' && first != '(' {
        return None;
    }
    if char_before(text, p).is_some_and(|c| c == '.' || c == '-' || is_word(c)) {
        return None;
    }
    memo.reset(p);
    if first == '(' {
        // second alternative: \(\d{1,4}\)[ .-]?  (the first needs a '+')
        return paren_then_body(text, p, memo);
    }
    // first alternative: \+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?
    for end in digit_choices(text, p + 1, 1, 3) {
        for s in optional_sep(text, end) {
            // the optional paren group is greedy: with it first, then without
            if let Some(e) = paren_then_body(text, s, memo) {
                return Some(e);
            }
            if let Some(e) = structured_body(text, s, memo) {
                return Some(e);
            }
        }
    }
    None
}

/// Raw `finditer` matches of the structured phone pattern (before `phone_ok`).
pub(crate) fn phone_structured(text: &str, emit: impl FnMut(usize, usize)) {
    let mut memo = Memo::new();
    find_iter(
        text,
        |b| b == b'+' || b == b'(',
        |p| phone_structured_at(text, p, &mut memo),
        emit,
    );
}

// --- phone, bare -------------------------------------------------------------
//
// Python: (?<![\w.+(-])\d{2,4}(?:[ .-]\d{2,4}){2,4}(?![\w-])(?!\.\d)
//
// Separators are mandatory here, so a group can only end where a separator or
// the tail follows; the search is a narrow tree and needs no memo.

pub(crate) const PHONE_BARE_SRC: &str =
    r"(?<![\w.+(-])\d{2,4}(?:[ .-]\d{2,4}){2,4}(?![\w-])(?!\.\d)";

fn bare_groups(text: &str, pos: usize, count: u8) -> Option<usize> {
    if count < 4 && matches!(char_after(text, pos), Some(' ' | '.' | '-')) {
        for end in digit_choices(text, pos + 1, 2, 4) {
            if let Some(e) = bare_groups(text, end, count + 1) {
                return Some(e);
            }
        }
    }
    (count >= 2 && phone_tail_ok(text, pos)).then_some(pos)
}

fn phone_bare_at(text: &str, p: usize) -> Option<usize> {
    if !char_after(text, p).is_some_and(is_digit) {
        return None;
    }
    if char_before(text, p).is_some_and(|c| matches!(c, '.' | '+' | '(' | '-') || is_word(c)) {
        return None;
    }
    digit_choices(text, p, 2, 4).find_map(|end| bare_groups(text, end, 0))
}

/// Raw `finditer` matches of the bare phone pattern (before `phone_ok`).
pub(crate) fn phone_bare(text: &str, emit: impl FnMut(usize, usize)) {
    find_iter(
        text,
        |b| b.is_ascii_digit(),
        |p| phone_bare_at(text, p),
        emit,
    );
}

// --- phone_ok ----------------------------------------------------------------

/// The first 11 characters of `s` on the stack, and how many there are
/// (12 meaning "more than 11": too long for either shape).
fn shape_chars(s: &str) -> ([char; 11], usize) {
    let mut buf = ['\0'; 11];
    let mut len = 0;
    for c in s.chars() {
        if len == 11 {
            return (buf, 12);
        }
        buf[len] = c;
        len += 1;
    }
    (buf, len)
}

/// `\A(?:19|20)\d{2}-\d{2}-\d{2}\Z`
fn date_shape(cs: &[char]) -> bool {
    cs.len() == 10
        && matches!((cs[0], cs[1]), ('1', '9') | ('2', '0'))
        && [2, 3, 5, 6, 8, 9].iter().all(|&i| is_digit(cs[i]))
        && cs[4] == '-'
        && cs[7] == '-'
}

/// `\A\d{3}-\d{2}-\d{4}\Z`
fn ssn_shape(cs: &[char]) -> bool {
    cs.len() == 11
        && [0, 1, 2, 4, 5, 7, 8, 9, 10]
            .iter()
            .all(|&i| is_digit(cs[i]))
        && cs[3] == '-'
        && cs[6] == '-'
}

/// Python `phone_ok`: not an ISO date or SSN shape (after `str.strip()`), and
/// 7-15 decimal digits.
pub(crate) fn phone_ok(m: &str) -> bool {
    let (buf, len) = shape_chars(m.trim_matches(|c: char| is_space(c)));
    if len <= 11 && (date_shape(&buf[..len]) || ssn_shape(&buf[..len])) {
        return false;
    }
    let digits = m.chars().filter(|&c| is_digit(c)).count();
    (7..=15).contains(&digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(scan: fn(&str, &mut dyn FnMut(usize, usize)), text: &str) -> Vec<&str> {
        let mut v = Vec::new();
        scan(text, &mut |s, e| v.push((s, e)));
        v.into_iter().map(|(s, e)| &text[s..e]).collect()
    }
    fn cc(t: &str, f: &mut dyn FnMut(usize, usize)) {
        credit_card(t, f)
    }
    fn ps(t: &str, f: &mut dyn FnMut(usize, usize)) {
        phone_structured(t, f)
    }
    fn pb(t: &str, f: &mut dyn FnMut(usize, usize)) {
        phone_bare(t, f)
    }

    #[test]
    fn credit_card_backtracks_to_a_shorter_match() {
        // 20 digits in groups of 4: t=19,18,17 end inside a group ((?![\d-]) fails),
        // t=16 ends before a space and is accepted.
        assert_eq!(all(cc, "4111 1111 1111 1111 1111"), ["4111 1111 1111 1111"]);
        assert_eq!(all(cc, "4111-1111-1111-1111"), ["4111-1111-1111-1111"]);
        assert_eq!(all(cc, "x4111111111111111y"), ["4111111111111111"]);
        assert!(all(cc, "-4111111111111111").is_empty()); // lookbehind
        assert!(all(cc, "4111111111111111-").is_empty()); // every t ends before a digit or '-'
        assert!(all(cc, "123456789012").is_empty()); // 12 digits
    }

    #[test]
    fn luhn() {
        assert!(luhn_ok("4111 1111 1111 1111"));
        assert!(!luhn_ok("4111 1111 1111 1112"));
        assert!(luhn_ok("٤١١١١١١١١١١١١١١١")); // Unicode digits by value
    }

    #[test]
    fn structured_phone() {
        assert_eq!(all(ps, "call +1 (415) 555-2671 now"), ["+1 (415) 555-2671"]);
        assert_eq!(all(ps, "(415) 555-2671"), ["(415) 555-2671"]);
        assert_eq!(all(ps, "+12345678"), ["+12345678"]); // body splits 456|78
        assert!(all(ps, "a+1 555 1234").is_empty()); // lookbehind \w
    }

    #[test]
    fn bare_phone() {
        assert_eq!(all(pb, "555 123 4567"), ["555 123 4567"]);
        assert!(all(pb, "555 123").is_empty()); // needs >= 3 groups
        assert!(all(pb, "+555 123 4567").is_empty()); // lookbehind '+'
    }

    #[test]
    fn phone_ok_rules() {
        assert!(phone_ok("555 123 4567"));
        assert!(!phone_ok("2024-01-15")); // ISO date
        assert!(!phone_ok("123-45-6789")); // SSN shape
        assert!(!phone_ok("12 34 56")); // 6 digits
    }
}
