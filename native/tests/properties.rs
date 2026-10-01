//! Property tests for the pure-Rust core (`cargo test --no-default-features`).
//!
//! * Robustness: any Unicode input scans without panicking, and every reported
//!   span lies on character boundaries inside the text.
//! * Chunk-cut preservation: scanning a text in windows exactly the way the
//!   streaming engine does (`engine.stream_windows`: carried left context, emit
//!   point retreated so no match straddles it, matches in the carried context
//!   dropped) yields exactly the matches of one whole-text scan, for arbitrary
//!   chunk sizes. Entities cut by a chunk boundary are found once, whole.
//!
//! Byte-for-byte parity with the Python tier is tested from Python
//! (`tests/test_native_backend.py`), where the oracle lives.

use proptest::prelude::*;
use safestream_native::{scan, scan_labeled, RawMatch, Scan};
use std::collections::BTreeSet;

const TOKENS: &[&str] = &[
    "bob.smith@corp.example.com",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    "sk_live_abcdefghijklmnop1234567890",
    "4111 1111 1111 1111",
    "4111-1111-1111-1111",
    "4111111111111111",
    "+1 (415) 555-2671",
    "(020) 7946 0958",
    "415 555 2671",
    "123-45-6789",
    "10.20.30.40",
    "2001:db8::8a2e:370:7334",
    "fe80::1",
    "٩٩.٩.٩.٩",
    "١٢٣-٤٥-٦٧٨٩",
    "文字",
    "2024-01-15",
    "id 956227 bytes 76323",
];

/// Separators always contain a letter, so no digit/separator chain runs from one
/// token into the next. (Card and phone matching is chained like `re.finditer`:
/// an unbroken run of digits and spaces longer than the overlap could be split
/// differently mid-run, in the Python tier too. Real text breaks such runs.)
const SEPS: &[&str] = &[" x ", "\nq ", ", z ", " and ", " é "];

fn text_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec((0..TOKENS.len(), 0..SEPS.len()), 1..60).prop_map(|parts| {
        let mut s = String::new();
        for (t, sep) in parts {
            s.push_str(TOKENS[t]);
            s.push_str(SEPS[sep]);
        }
        s
    })
}

fn whole(text: &str) -> BTreeSet<(usize, usize, u16)> {
    let mut out = Vec::new();
    assert_eq!(scan(text, &mut out), Ok(Scan::Exact));
    out.iter().map(|m| (m.start, m.end, m.pattern)).collect()
}

/// Floor `i` to a char boundary of `s`.
fn floor(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// `engine.stream_windows`, at the raw-match level and in byte offsets.
fn streamed(text: &str, chunk: usize, overlap: usize) -> BTreeSet<(usize, usize, u16)> {
    let min_emit = overlap.max(chunk).max(1);
    let mut found = BTreeSet::new();
    let mut emitted = 0usize; // absolute offset of the first unemitted byte
    let mut out: Vec<RawMatch> = Vec::new();
    loop {
        let prefix_start = floor(text, emitted.saturating_sub(overlap));
        let at_end = text.len() - emitted < overlap + min_emit;
        let window_end = if at_end {
            text.len()
        } else {
            floor(text, emitted + overlap + min_emit)
        };
        let window = &text[prefix_start..window_end];
        assert_eq!(scan(window, &mut out), Ok(Scan::Exact));
        let shift = emitted - prefix_start;
        // matches relative to the buffer (the part after the carried prefix)
        let rel: Vec<(isize, isize, u16)> = out
            .iter()
            .map(|m| {
                (
                    m.start as isize - shift as isize,
                    m.end as isize - shift as isize,
                    m.pattern,
                )
            })
            .collect();
        let buffer_len = (window_end - emitted) as isize;
        let mut emit_upto = if at_end {
            buffer_len
        } else {
            buffer_len - overlap as isize
        };
        // _retreat_boundary: never cut through a match
        loop {
            let crossing = rel
                .iter()
                .filter(|&&(s, e, _)| s < emit_upto && emit_upto < e)
                .map(|m| m.0)
                .min();
            match crossing {
                Some(s) => emit_upto = s,
                None => break,
            }
        }
        if emit_upto <= 0 && !at_end {
            // a match pins the whole buffer: the engine waits for more input
            panic!("test texts never pin a whole {overlap}-byte buffer");
        }
        for &(s, e, p) in &rel {
            if s >= 0 && e <= emit_upto {
                found.insert((
                    (emitted as isize + s) as usize,
                    (emitted as isize + e) as usize,
                    p,
                ));
            }
        }
        emitted += emit_upto.max(0) as usize;
        if at_end {
            return found;
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_unicode_never_panics(text in "\\PC{0,400}") {
        let mut out = Vec::new();
        if scan(&text, &mut out).unwrap() == Scan::Exact {
            for m in &out {
                prop_assert!(m.start < m.end && m.end <= text.len());
                prop_assert!(text.is_char_boundary(m.start) && text.is_char_boundary(m.end));
            }
        } else {
            prop_assert!(out.is_empty());
        }
        let mut labeled = Vec::new();
        if scan_labeled(&text, &mut labeled).unwrap() == Scan::Exact {
            for m in &labeled {
                prop_assert!(m.start <= m.value_start && m.value_start < m.value_end);
                prop_assert!(m.value_end <= text.len() && text.is_char_boundary(m.value_end));
            }
        }
    }

    #[test]
    fn digit_soup_never_panics(text in "[0-9٣ .()+\\-x_]{0,300}") {
        let mut out = Vec::new();
        prop_assert_eq!(scan(&text, &mut out).unwrap(), Scan::Exact);
    }

    #[test]
    fn chunk_cuts_preserve_every_match(
        text in text_strategy(),
        chunk in 1usize..400,
    ) {
        // 256 bytes covers the longest token here (the JWT) plus its context
        prop_assert_eq!(streamed(&text, chunk, 256), whole(&text));
    }
}

#[test]
fn a_token_split_at_every_offset_is_found_once() {
    // every possible cut through a card, a phone and a key: one match each
    let text = "pay 4111 1111 1111 1111 now, call +1 (415) 555-2671 x key AKIAIOSFODNN7EXAMPLE q";
    let expected = whole(text);
    assert_eq!(expected.len(), 3, "{expected:?}");
    for chunk in 1..text.len() {
        assert_eq!(streamed(text, chunk, 48), expected, "chunk={chunk}");
    }
}
