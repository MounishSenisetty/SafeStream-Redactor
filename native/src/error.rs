//! Structured errors. No production path panics: every failure surfaces as an
//! [`Error`] that the Python bindings map to a Python exception.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A built-in pattern failed to compile (a build defect, e.g. a regex-crate
    /// size limit lowered below what a pattern needs).
    Pattern { name: &'static str, message: String },
    /// Growing an output buffer failed (the process hit its memory limit,
    /// e.g. an `RLIMIT_AS` cap). Reported instead of aborting the process.
    OutOfMemory,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pattern { name, message } => {
                write!(f, "native pattern {name:?} failed to compile: {message}")
            }
            Error::OutOfMemory => {
                f.write_str("native scanner could not allocate its output buffer")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Push without aborting on allocation failure: `Vec::push` aborts the whole
/// process when the allocator refuses, which under `--memory-limit` (a kernel
/// `RLIMIT_AS` cap) would kill the interpreter instead of letting it exit cleanly.
#[inline]
pub(crate) fn try_push<T>(out: &mut Vec<T>, item: T) -> Result<(), Error> {
    if out.len() == out.capacity() {
        out.try_reserve(out.len().max(16))
            .map_err(|_| Error::OutOfMemory)?;
    }
    out.push(item);
    Ok(())
}
