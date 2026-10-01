//! Dump how the locked `regex` crate classifies every Unicode scalar value:
//! `\w`, `\d`, `\s`, and which ASCII letters each character matches under
//! `(?i)`. `tools/gen_unicode_tables.py` diffs this against every supported
//! CPython to find the characters where the two engines disagree.
//!
//!     cargo run --release --no-default-features --example dump_classes > rust.json

use regex::Regex;

fn ranges(pred: impl Fn(char) -> bool) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        if pred(c) {
            match out.last_mut() {
                Some(last) if last.1 + 1 == cp => last.1 = cp,
                _ => out.push((cp, cp)),
            }
        }
    }
    out
}

fn json(r: &[(u32, u32)]) -> String {
    let items: Vec<String> = r.iter().map(|(a, b)| format!("[{a},{b}]")).collect();
    format!("[{}]", items.join(","))
}

fn main() -> Result<(), regex::Error> {
    let one = |src: &str| -> Result<Regex, regex::Error> { Regex::new(&format!(r"\A(?:{src})\z")) };
    let (w, d, s) = (one(r"\w")?, one(r"\d")?, one(r"\s")?);
    let mut buf = [0u8; 4];
    let mut fields = vec![
        format!(
            "\"w\":{}",
            json(&ranges(|c| w.is_match(c.encode_utf8(&mut buf.clone()))))
        ),
        format!(
            "\"d\":{}",
            json(&ranges(|c| d.is_match(c.encode_utf8(&mut buf.clone()))))
        ),
        format!(
            "\"s\":{}",
            json(&ranges(|c| s.is_match(c.encode_utf8(&mut buf.clone()))))
        ),
    ];
    // case-insensitive matches of each ASCII letter, non-ASCII characters only
    let mut fold = Vec::new();
    for letter in 'a'..='z' {
        let re = one(&format!("(?i){letter}"))?;
        let hits: Vec<String> = (0x80..=0x10FFFFu32)
            .filter_map(char::from_u32)
            .filter(|c| re.is_match(c.encode_utf8(&mut buf)))
            .map(|c| (c as u32).to_string())
            .collect();
        fold.push(format!("\"{letter}\":[{}]", hits.join(",")));
    }
    fields.push(format!("\"fold\":{{{}}}", fold.join(",")));
    // the case-insensitive ASCII letter classes used by the labeled-id rules
    for (key, cls) in [("fold_upper", "[A-Z]"), ("fold_lower", "[a-z]")] {
        let re = one(&format!("(?i){cls}"))?;
        let hits = ranges(|c| !c.is_ascii() && re.is_match(c.encode_utf8(&mut buf.clone())));
        fields.push(format!("\"{key}\":{}", json(&hits)));
    }
    println!("{{{}}}", fields.join(","));
    Ok(())
}
