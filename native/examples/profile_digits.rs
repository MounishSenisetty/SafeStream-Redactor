//! Drive one scanner family for profiling (callgrind):
//!     cargo build --release --no-default-features --example profile_digits
//!     valgrind --tool=callgrind target/release/examples/profile_digits digits
use safestream_native::{bench_hooks, corpus::log_corpus};

fn main() -> Result<(), safestream_native::Error> {
    let which = std::env::args().nth(1).unwrap_or_else(|| "digits".into());
    let text = log_corpus(1 << 20, 0, 7);
    let mut out = Vec::new();
    let mut n = 0;
    for _ in 0..3 {
        if which == "digits" {
            bench_hooks::digits_only(&text, &mut out)?;
        } else {
            bench_hooks::regex_only(&text, &mut out)?;
        }
        n += out.len();
    }
    println!("{n}");
    Ok(())
}
