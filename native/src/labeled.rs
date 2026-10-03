//! Native port of `detectors/labeled_id.py`: a cue word, a bounded gap, and a
//! value group (`Student ID: 202184673` -> the value span).
//!
//! The rules are compiled from the same cue/separator/value fragments as the
//! Python module, so [`rule_sources`] reproduces its regex sources byte-for-byte
//! for the spec guard. In Python each rule starts with `\b(?:cue)`, which `re`
//! must try at every position (13–40 MB/s per rule, six rules); here the
//! case-insensitive cue alternation becomes a literal prefilter and the scan
//! skips straight to candidate cues.

use crate::error::{try_push, Error};
use crate::patterns::WordBounded;
use std::sync::OnceLock;

/// `labeled_id._SEP`.
const SEP: &str =
    r"(?:\s*(?:number|num|no|id|code|#|:|=|-|\.|is|of)\b)*\s*(?:[:=#\-.\u2013\u2014\u25ba|]\s*)?";

/// `labeled_id._RULES`: (cue alternation, value pattern, entity type, confidence).
pub const RULES: &[(&str, &str, &str, f64)] = &[
    (
        r"ssn|social[\s-]?security(?:\s*(?:no|number|#))?|sin|national\s*id",
        r"(\d{3}[-\s]?\d{2}[-\s]?\d{4}|\d{9})",
        "id_number",
        0.8,
    ),
    (
        r"dob|date\s*of\s*birth|birth\s*date|born(?:\s*on)?",
        concat!(
            r"(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}",
            r"|\d{1,2}(?:st|nd|rd|th)?[ \t]{1,3}(?:of[ \t]{1,3})?",
            r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?",
            r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)",
            r"\.?,?[ \t]{1,3}\d{2,4}",
            r"|(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?",
            r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)",
            r"\.?[ \t]{1,3}\d{1,2}(?:st|nd|rd|th)?,?[ \t]{1,3}\d{2,4})"
        ),
        "dob",
        0.8,
    ),
    (
        r"phone|tel(?:ephone)?|mobile|cell|fax|call|contact\s*(?:no|number)",
        r"(\+?\d[\d \t().\-\u2013\u25ba]{6,61}\d)",
        "phone",
        0.8,
    ),
    (
        r"card(?:\s*(?:no|number|#))?|credit\s*card|debit\s*card|pan",
        r"((?:\d[ -]?){12,18}\d)",
        "credit_card",
        0.85,
    ),
    (
        r"account|acct|routing|aba|iban|swift|bic|bank|sort\s*code",
        r"([A-Z]{2}\d{2}[A-Z0-9]{6,30}|[A-Z]{1,6}-\d[A-Z0-9-]{3,56}|\d[\d\s-]{4,62}\d)",
        "id_number",
        0.8,
    ),
    (
        concat!(
            r"student|employee|emp|staff|member|customer|client|patient|",
            r"badge|tax|medical\s*record|mrn|npi|licen[cs]e|passport|",
            r"national\s*id|registration|enrol?lment"
        ),
        r"([A-Za-z]{0,6}[-/]?\d[A-Za-z0-9-]{2,56})",
        "id_number",
        0.75,
    ),
    (
        r"case\s*(?:no|number|num)|docket|policy|claim|visa|record",
        r"([A-Za-z]{0,6}[-/]?\d[A-Za-z0-9-]{2,56})",
        "id_number",
        0.75,
    ),
];

/// The Python source of each rule (`rf"\b(?:{cue})\b{_SEP}{value}"`, compiled
/// with `re.IGNORECASE`).
pub fn rule_sources() -> Vec<String> {
    RULES
        .iter()
        .map(|(cue, value, _, _)| format!(r"\b(?:{cue})\b{SEP}{value}"))
        .collect()
}

/// A labeled match, byte offsets: the whole `cue … value` match start and the
/// value group (the emitted span).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabeledMatch {
    pub start: usize,
    pub value_start: usize,
    pub value_end: usize,
    pub rule: u8,
}

fn engine() -> Result<&'static [WordBounded], Error> {
    static ENGINE: OnceLock<Result<Vec<WordBounded>, Error>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            rule_sources()
                .iter()
                .map(|src| WordBounded::new("labeled_identifier", &format!("(?i){src}")))
                .collect()
        })
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

/// Every rule match in `text`, in rule order then position (as the Python
/// detector emits them). The `_CUE_WINDOW` distance guard is measured in
/// characters, so the caller applies it after offset conversion.
pub(crate) fn scan_labeled(text: &str, out: &mut Vec<LabeledMatch>) -> Result<(), Error> {
    for (rule, re) in engine()?.iter().enumerate() {
        re.for_each(text, true, |(start, _end), value| {
            let Some((value_start, value_end)) = value else {
                return Ok(());
            };
            let m = LabeledMatch {
                start,
                value_start,
                value_end,
                rule: rule as u8,
            };
            try_push(out, m)
        })?;
    }
    Ok(())
}

pub fn warm_up() -> Result<(), Error> {
    engine().map(|_| ())
}
