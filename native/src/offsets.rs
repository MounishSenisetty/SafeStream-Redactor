//! Byte offsets (what Rust's `str` and `regex` use) to character offsets (what
//! Python's `str` and the `Detection` type use).

use crate::error::Error;

/// A reusable byte-offset -> char-offset table for one text.
///
/// Built from just the offsets that matches use: sort them, then walk the text
/// once, counting characters between consecutive offsets. The count is a filter
/// over bytes (a byte starts a character unless it is a UTF-8 continuation byte),
/// which the compiler vectorises. Keep one `OffsetMap` per thread and reuse it:
/// after warm-up a conversion allocates nothing.
#[derive(Default)]
pub struct OffsetMap {
    keys: Vec<usize>,
    vals: Vec<usize>,
    ascii: bool,
}

#[inline]
fn count_chars(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| (b as i8) >= -0x40).count()
}

impl OffsetMap {
    pub fn new() -> OffsetMap {
        OffsetMap::default()
    }

    /// Prepare to translate `offsets` (byte offsets on char boundaries of `text`).
    pub fn build(&mut self, text: &str, offsets: impl Iterator<Item = usize>) -> Result<(), Error> {
        self.keys.clear();
        self.vals.clear();
        self.ascii = text.is_ascii();
        if self.ascii {
            return Ok(()); // byte offset == char offset
        }
        for o in offsets {
            if self.keys.len() == self.keys.capacity() {
                self.keys
                    .try_reserve(self.keys.len().max(16))
                    .map_err(|_| Error::OutOfMemory)?;
            }
            self.keys.push(o);
        }
        self.keys.sort_unstable();
        self.keys.dedup();
        self.vals
            .try_reserve(self.keys.len())
            .map_err(|_| Error::OutOfMemory)?;
        let bytes = text.as_bytes();
        let (mut byte, mut chars) = (0usize, 0usize);
        for &k in &self.keys {
            let k = k.min(bytes.len());
            chars += count_chars(&bytes[byte..k]);
            byte = k;
            self.vals.push(chars);
        }
        Ok(())
    }

    /// The char offset of byte offset `b` (which must have been passed to `build`).
    #[inline]
    pub fn get(&self, text: &str, b: usize) -> usize {
        if self.ascii {
            return b;
        }
        match self.keys.binary_search(&b) {
            Ok(i) => self.vals[i],
            // not registered: correct but slow, never reached by the scanners
            Err(_) => count_chars(&text.as_bytes()[..b.min(text.len())]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_char_indices() {
        let text = "a文字b\u{1F600}cé";
        let offs: Vec<usize> = text
            .char_indices()
            .map(|(b, _)| b)
            .chain([text.len()])
            .collect();
        let mut map = OffsetMap::new();
        map.build(text, offs.iter().copied()).unwrap();
        for (ci, &b) in offs.iter().enumerate() {
            assert_eq!(map.get(text, b), ci);
        }
    }
}
