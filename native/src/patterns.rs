//! The pattern table and the regex-backed scanners.
//!
//! Each regex pattern is a separate compiled `Regex` scanned with `find_iter`, so
//! the crate's required-literal prefilter (memchr / Teddy, SIMD) skips straight
//! to candidate positions. A `RegexSet` was measured and rejected: the combined
//! automaton is bloated by `private_key` and loses the per-pattern literal
//! prefilters (~6 MB/s vs 400–1200 MB/s; see `docs/NATIVE_CORE.md`).

use crate::error::{try_push, Error};
use crate::unicode::{digit_value, is_digit, is_word};
use crate::RawMatch;
use regex::{Regex, RegexBuilder};
use regex_automata::{meta, Anchored, Input};
use std::net::Ipv6Addr;
use std::sync::OnceLock;

/// How a pattern is matched and validated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The regex is exact: every match is a detection.
    Simple,
    /// Lookaround-free candidate + boundary check + validator (`_lookaround_free.py`).
    Ssn,
    Ipv4,
    Ipv6,
    /// MAC / EUI-64: candidate + boundary + one consistent separator, 6..20 groups.
    Mac,
    /// The detection is capture group 1 (a labeled value); the regex is exact.
    Captured,
    /// Group 1 plus the original's case-insensitive `(?![A-Za-z0-9/+])` after it.
    AwsSecret,
    /// Hand-written linear scanners (`digits.rs`), no regex.
    CreditCard,
    PhoneStructured,
    PhoneBare,
}

pub struct PatternSpec {
    pub name: &'static str,
    pub confidence: f64,
    /// The Python source, byte-for-byte. Exposed so the spec guard can check it.
    pub source: &'static str,
    pub kind: Kind,
}

/// The patterns the native core covers. `source` is the Python spec; the
/// differential tests and the runtime spec guard check it.
pub const PATTERNS: &[PatternSpec] = &[
    PatternSpec {
        name: "email",
        confidence: 0.95,
        source: r"\b[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "private_key",
        confidence: 0.99,
        source: r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY-----[A-Za-z0-9+/=\s]{1,8100}?-----END [A-Z0-9 ]{0,20}PRIVATE KEY-----",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "jwt",
        confidence: 0.95,
        source: r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "aws_key",
        confidence: 0.98,
        source: r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "github_token",
        confidence: 0.98,
        source: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "slack_token",
        confidence: 0.98,
        source: r"\bxox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,3}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "slack_webhook",
        confidence: 0.98,
        source: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "stripe_key",
        confidence: 0.97,
        source: r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "google_api_key",
        confidence: 0.95,
        source: r"\bAIza[0-9A-Za-z_-]{35}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "sendgrid_key",
        confidence: 0.98,
        source: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "twilio_key",
        confidence: 0.9,
        source: r"\bSK[0-9a-f]{32}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "npm_token",
        confidence: 0.98,
        source: r"\bnpm_[A-Za-z0-9]{36}\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "ssn",
        confidence: 0.85,
        source: r"\d{3}-\d{2}-\d{4}",
        kind: Kind::Ssn,
    },
    PatternSpec {
        name: "ipv4",
        confidence: 0.9,
        source: r"\d{1,3}(?:\.\d{1,3}){3}",
        kind: Kind::Ipv4,
    },
    PatternSpec {
        name: "ipv6",
        confidence: 0.9,
        source: r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}",
        kind: Kind::Ipv6,
    },
    // MAC: the lookaround-free candidate from `_lookaround_free.py`; the original's
    // lookarounds and `([:-])...\1` backreference are re-checked in `mac_ok`.
    PatternSpec {
        name: "mac_address",
        confidence: 0.85,
        source: r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2})+",
        kind: Kind::Mac,
    },
    // AWS account id, only where AWS itself frames one; the Python sources are
    // already lookaround-free, and the detection is the 12-digit group.
    PatternSpec {
        name: "aws_account_id",
        confidence: 0.85,
        source: r"\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12})[:/]",
        kind: Kind::Captured,
    },
    PatternSpec {
        name: "aws_account_id",
        confidence: 0.85,
        source: r"\.amazonaws\.com(?:\.cn)?/(\d{12})\b",
        kind: Kind::Captured,
    },
    PatternSpec {
        name: "aws_account_id",
        confidence: 0.85,
        source: r"\b(\d{12})\.dkr\.ecr\.",
        kind: Kind::Captured,
    },
    // Postal addresses (`deterministic._STREET_SRC` / `_CITY_ZIP_SRC`): exact,
    // lookaround-free, and line-bounded (gaps are `[ \t]` only).
    PatternSpec {
        name: "address",
        confidence: 0.8,
        source: concat!(
            r"\b[0-9]{1,6}[ \t]+(?:[A-Z0-9][A-Za-z0-9'-]*\.?[ \t]+){1,4}",
            r"(?:Street|STREET|St|ST|Avenue|AVENUE|Ave|AVE|Road|ROAD|Rd|RD|Boulevard|BOULEVARD",
            r"|Blvd|BLVD|Lane|LANE|Ln|LN|Drive|DRIVE|Dr|DR|Way|WAY|Court|COURT|Ct|CT|Place",
            r"|PLACE|Pl|PL|Parkway|PARKWAY|Pkwy|PKWY|Terrace|TERRACE|Circle|CIRCLE|Highway",
            r"|HIGHWAY|Hwy|HWY|Square|SQUARE)\b",
        ),
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "address",
        confidence: 0.8,
        source: concat!(
            r"\b[A-Z][A-Za-z]+(?:[ \t][A-Z][A-Za-z]+){0,2},[ \t]+(?:",
            r"AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT",
            r"|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|PR|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY",
            r"|Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware",
            r"|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana",
            r"|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana",
            r"|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina",
            r"|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina",
            r"|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia",
            r"|Wisconsin|Wyoming),?[ \t]+[0-9]{5}(?:-[0-9]{4})?\b",
        ),
        kind: Kind::Simple,
    },
    // The label-gated credentials. anthropic/openai/aws_secret use the
    // lookaround-free sources from `_lookaround_free.py` (proven equal to the
    // originals there); url_credentials and api_key need no rewrite.
    PatternSpec {
        name: "anthropic_key",
        confidence: 0.98,
        source: r"\bsk-ant-[A-Za-z0-9_-]{19,}[A-Za-z0-9_]\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "openai_key",
        confidence: 0.95,
        source: r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{19,}[A-Za-z0-9_]|[A-Za-z0-9]{32,})\b",
        kind: Kind::Simple,
    },
    PatternSpec {
        name: "url_credentials",
        confidence: 0.97,
        source: r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:([^\s@/]{1,128})@[^\s@]",
        kind: Kind::Captured,
    },
    PatternSpec {
        name: "aws_secret",
        confidence: 0.9,
        source: r#"(?i)aws[_\s-]*secret[_\s-]*(?:access[_\s-]*)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})"#,
        kind: Kind::AwsSecret,
    },
    PatternSpec {
        name: "api_key",
        confidence: 0.75,
        source: concat!(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token",
            r#"|token|password|passwd|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_@!#$%^&*./+\-]{12,128})[\"']?"#
        ),
        kind: Kind::Captured,
    },
    PatternSpec {
        name: "credit_card",
        confidence: 0.9,
        source: r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])",
        kind: Kind::CreditCard,
    },
    PatternSpec {
        name: "phone",
        confidence: 0.6,
        source: r"(?<![\w.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{1,4}\)[ .-]?)\d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-])(?!\.\d)",
        kind: Kind::PhoneStructured,
    },
    PatternSpec {
        name: "phone",
        confidence: 0.45,
        source: r"(?<![\w.+(-])\d{2,4}(?:[ .-]\d{2,4}){2,4}(?![\w-])(?!\.\d)",
        kind: Kind::PhoneBare,
    },
];

/// Compile-size caps. They bound the memory any one automaton (and each lazy-DFA
/// cache) can take, independent of the input; the built-in patterns fit well
/// inside them, and a test proves every pattern compiles under them.
const SIZE_LIMIT: usize = 16 << 20;
const DFA_SIZE_LIMIT: usize = 4 << 20;

/// The Rust source for a Python pattern. CPython's `\s` also matches the four
/// ASCII separators `\x1c`–`\x1f`; Rust's does not, so they are added explicitly.
pub(crate) fn rust_source(source: &str) -> String {
    source.replace(r"\s", r"[\s\x1C-\x1F]")
}

pub(crate) fn compile(name: &'static str, source: &str) -> Result<Regex, Error> {
    RegexBuilder::new(&rust_source(source))
        .size_limit(SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|e| Error::Pattern {
            name,
            message: e.to_string(),
        })
}

/// A byte span `(start, end)`.
pub(crate) type Span = (usize, usize);

/// Rejected candidates per text before [`WordBounded`] falls back to the exact
/// regex (see there).
const MAX_REJECTED: usize = 64;

/// A pattern compiled so that Unicode `\b` stays fast on non-ASCII text.
///
/// The lazy DFA cannot evaluate a Unicode word boundary once it reads a
/// non-ASCII byte, so on such text the `regex` crate runs a much slower engine
/// over the rest of the haystack: one accented name or curly quote per window
/// made whole windows 10-20x slower. On non-ASCII text this type instead finds
/// candidate starts with `relaxed`, the pattern with every `\b` removed (its
/// match starts are a superset of the exact pattern's, and it has no assertion
/// the DFA must give up on), and verifies each candidate with `anchored`, the
/// exact pattern searched anchored at that start, which costs only the
/// candidate's own length. Candidates are tried left to right and the scan
/// resumes after each match, which is exactly `captures_iter`'s leftmost-first
/// order. ASCII text, and patterns without `\b`, use the exact regex directly.
///
/// A candidate the exact pattern rejects costs a relaxed search that may scan a
/// long run again from the next character, so hostile text (a 70K-character
/// word run glued to an accented letter, before an `@`) would be quadratic.
/// After [`MAX_REJECTED`] rejections in one text the scan therefore finishes
/// with the exact regex's own linear-time search instead: same matches, bounded
/// worst case.
pub(crate) struct WordBounded {
    exact: Regex,
    fast_path: Option<(Regex, meta::Regex)>,
}

impl WordBounded {
    pub(crate) fn new(name: &'static str, source: &str) -> Result<Self, Error> {
        let exact = compile(name, source)?;
        if !source.contains(r"\b") {
            return Ok(Self {
                exact,
                fast_path: None,
            });
        }
        let relaxed = compile(name, &source.replace(r"\b", ""))?;
        let anchored = meta::Regex::builder()
            .configure(
                meta::Config::new()
                    .nfa_size_limit(Some(SIZE_LIMIT))
                    .hybrid_cache_capacity(DFA_SIZE_LIMIT),
            )
            .build(&rust_source(source))
            .map_err(|e| Error::Pattern {
                name,
                message: e.to_string(),
            })?;
        Ok(Self {
            exact,
            fast_path: Some((relaxed, anchored)),
        })
    }

    /// Call `f(whole, group_1)` for every match in `text`, in order (byte spans).
    /// `group_1` is filled only when `want_group` is set.
    pub(crate) fn for_each(
        &self,
        text: &str,
        want_group: bool,
        mut f: impl FnMut(Span, Option<Span>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some((relaxed, anchored)) = self.fast_path.as_ref().filter(|_| !text.is_ascii()) else {
            return self.exact_from(text, 0, want_group, f);
        };
        let mut caps = anchored.create_captures();
        let mut pos = 0;
        let mut rejected = 0;
        while let Some(candidate) = relaxed.find_at(text, pos) {
            if rejected >= MAX_REJECTED {
                return self.exact_from(text, pos, want_group, f);
            }
            let start = candidate.start();
            let input = Input::new(text).range(start..).anchored(Anchored::Yes);
            let found = if want_group {
                anchored.search_captures(&input, &mut caps);
                caps.get_match().map(|m| {
                    let group = caps.get_group(1).map(|g| (g.start, g.end));
                    ((m.start(), m.end()), group)
                })
            } else {
                anchored
                    .search(&input)
                    .map(|m| ((m.start(), m.end()), None))
            };
            pos = match found {
                Some((whole, group)) if whole.1 > start => {
                    f(whole, group)?;
                    whole.1
                }
                // no match here (or an empty one): the next candidate starts later
                _ => {
                    rejected += 1;
                    start + text[start..].chars().next().map_or(1, char::len_utf8)
                }
            };
            if pos > text.len() {
                break;
            }
        }
        Ok(())
    }

    /// The exact regex's matches starting at or after `pos`, as `captures_iter`
    /// would continue them (leftmost-first, resuming after each match).
    fn exact_from(
        &self,
        text: &str,
        mut pos: usize,
        want_group: bool,
        mut f: impl FnMut(Span, Option<Span>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        while pos <= text.len() {
            let (whole, group) = if want_group {
                let Some(caps) = self.exact.captures_at(text, pos) else {
                    break;
                };
                let Some(m) = caps.get(0) else { break };
                (
                    (m.start(), m.end()),
                    caps.get(1).map(|g| (g.start(), g.end())),
                )
            } else {
                let Some(m) = self.exact.find_at(text, pos) else {
                    break;
                };
                ((m.start(), m.end()), None)
            };
            f(whole, group)?;
            // built-in patterns never match empty; step over one anyway
            pos = if whole.1 > whole.0 {
                whole.1
            } else {
                whole.1 + text[whole.1..].chars().next().map_or(1, char::len_utf8)
            };
        }
        Ok(())
    }
}

/// Compiled regexes, indexed like `PATTERNS` (`None` for the scanner kinds).
fn engine() -> Result<&'static [Option<WordBounded>], Error> {
    static ENGINE: OnceLock<Result<Vec<Option<WordBounded>>, Error>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            PATTERNS
                .iter()
                .map(|p| match p.kind {
                    Kind::CreditCard | Kind::PhoneStructured | Kind::PhoneBare => Ok(None),
                    _ => WordBounded::new(p.name, p.source).map(Some),
                })
                .collect()
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

/// Compile every pattern now (the first scan would otherwise do it lazily).
pub fn warm_up() -> Result<(), Error> {
    engine().map(|_| ())
}

#[inline]
fn char_before(text: &str, start: usize) -> Option<char> {
    text[..start].chars().next_back()
}

#[inline]
fn char_after(text: &str, end: usize) -> Option<char> {
    text[end..].chars().next()
}

/// SSN's `(?<![\d-])…(?![\d-])`.
fn ssn_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    let bad = |c: char| c == '-' || is_digit(c);
    !char_before(text, start).is_some_and(bad) && !char_after(text, end).is_some_and(bad)
}

/// Python `ssn_ok`. Pure string comparisons (no `int()`), so it is exact for
/// Unicode-digit SSNs too. The candidate always has exactly two `-`.
fn ssn_ok(m: &str) -> bool {
    let mut it = m.split('-');
    let (Some(area), Some(group), Some(serial)) = (it.next(), it.next(), it.next()) else {
        return false;
    };
    if area == "000" || area == "666" || area.starts_with('9') {
        return false;
    }
    group != "00" && serial != "0000"
}

/// IPv4's `(?<![\d.])…(?!\d)(?!\.\d)`.
fn ipv4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if char_before(text, start).is_some_and(|c| c == '.' || is_digit(c)) {
        return false;
    }
    let mut after = text[end..].chars();
    match after.next() {
        None => true,
        Some('.') => !after.next().is_some_and(is_digit),
        Some(c) => !is_digit(c),
    }
}

/// Python `ipv4_ok`: each octet is "0", or has no ASCII leading zero and an
/// `int()` value <= 255 (Unicode digits included, via `digit_value`).
fn ipv4_ok(m: &str) -> bool {
    m.split('.').all(|o| {
        if o == "0" {
            return true;
        }
        if o.starts_with('0') {
            return false;
        }
        let mut val = 0u32;
        for c in o.chars() {
            match digit_value(c) {
                Some(d) => val = val * 10 + d,
                None => return false,
            }
        }
        val <= 255
    })
}

/// IPv6's `(?<![\w:.])…(?![\w:])`.
fn ipv6_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    !char_before(text, start).is_some_and(|c| c == ':' || c == '.' || is_word(c))
        && !char_after(text, end).is_some_and(|c| c == ':' || is_word(c))
}

/// MAC's `(?<![\w:.-])...(?![\w:-])` plus the backreference: one separator
/// throughout and 6..20 two-hex-digit groups (the candidate is ASCII, so its byte
/// length is its character length). Mirrors `_mac_boundary` / `_mac_value_ok`.
fn mac_ok(text: &str, start: usize, end: usize) -> bool {
    let m = &text[start..end];
    let groups = (m.len() + 1) / 3;
    !char_before(text, start).is_some_and(|c| matches!(c, ':' | '.' | '-') || is_word(c))
        && !char_after(text, end).is_some_and(|c| matches!(c, ':' | '-') || is_word(c))
        && m.contains(':') != m.contains('-')
        && (6..=20).contains(&groups)
}

/// The original AWS-secret pattern's `(?![A-Za-z0-9/+])`. It sits inside a
/// `(?i)` pattern, so in CPython it also rejects the two non-ASCII characters
/// that case-fold to an ASCII letter (`ſ`, the Kelvin sign). `İ`/`ı` fold
/// differently per engine and never reach here (`needs_python`).
fn aws_after_ok(text: &str, end: usize) -> bool {
    !char_after(text, end).is_some_and(|c| {
        c.is_ascii_alphanumeric() || c == '/' || c == '+' || c == '\u{17F}' || c == '\u{212A}'
    })
}

/// Python `ipv6_ok`: `ipaddress.IPv6Address(m)` parses (the candidate has no `%`).
fn ipv6_ok(m: &str) -> bool {
    m.parse::<Ipv6Addr>().is_ok()
}

/// Append every regex-pattern match in `text` to `out` (byte offsets).
pub(crate) fn scan_regex(text: &str, out: &mut Vec<RawMatch>) -> Result<(), Error> {
    for (idx, (spec, re)) in PATTERNS.iter().zip(engine()?).enumerate() {
        let Some(re) = re else { continue };
        let pattern = idx as u16;
        if matches!(spec.kind, Kind::Captured | Kind::AwsSecret) {
            // capture group 1 is the detection; matching resumes after the whole
            // match, as finditer does
            re.for_each(text, true, |_whole, value| {
                let Some((start, end)) = value else {
                    return Ok(());
                };
                if spec.kind == Kind::AwsSecret && !aws_after_ok(text, end) {
                    return Ok(());
                }
                try_push(
                    out,
                    RawMatch {
                        start,
                        end,
                        pattern,
                    },
                )
            })?;
            continue;
        }
        re.for_each(text, false, |(s, e), _| {
            let m = &text[s..e];
            let accept = match spec.kind {
                Kind::Simple => true,
                Kind::Ssn => ssn_boundary_ok(text, s, e) && ssn_ok(m),
                Kind::Ipv4 => ipv4_boundary_ok(text, s, e) && ipv4_ok(m),
                Kind::Ipv6 => ipv6_boundary_ok(text, s, e) && ipv6_ok(m),
                Kind::Mac => mac_ok(text, s, e),
                _ => false,
            };
            if accept {
                try_push(
                    out,
                    RawMatch {
                        start: s,
                        end: e,
                        pattern,
                    },
                )?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles_under_the_size_caps() {
        warm_up().expect("all built-in patterns compile");
    }

    #[test]
    fn whitespace_class_matches_cpython_separators() {
        let re = compile("t", r"a\sb").unwrap();
        for sep in ['\x1C', '\x1D', '\x1E', '\x1F', ' ', '\n', '\u{3000}'] {
            assert!(re.is_match(&format!("a{sep}b")), "{:?}", sep);
        }
    }
}
