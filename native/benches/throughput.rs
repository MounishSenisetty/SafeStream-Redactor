//! Throughput of the native scanners (Criterion).
//!
//!     cargo bench --no-default-features
//!
//! Corpora are 4 MiB of synthetic log text at 0%, 1%, 10% and 50% PII lines
//! (`src/corpus.rs`, mirroring `benchmarks/baseline.py`). Reported as bytes/s.
//!
//! * `scan/whole` — every native pattern over the whole corpus in one call.
//! * `scan/windows` — the same text the way the streaming engine feeds it:
//!   64 KiB chunks, each rescanned with an 8 KiB overlap (the default
//!   `chunk_size`/`overlap`), so the cost of the overlap re-scan is included.
//! * `scan/labeled` — the label-anchored identifier rules.
//! * `scan/entropy`, `scan/compound` — the statistical tiers.
//! * `scan/regex_only`, `scan/digits_only` — the two halves of `scan/whole`: the
//!   regex patterns, and the credit_card/phone linear scanners.
//! * `floor/count_lines` — a byte-counting pass over the same text: the
//!   memory-bandwidth ceiling any scanner on this machine is measured against.
//!
//! The Python tier's numbers come from `benchmarks/native_backend.py` and
//! `benchmarks/baseline.py`, which time the same patterns from Python.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use safestream_native::secrets::{CompoundParams, EntropyParams};
use safestream_native::{
    bench_hooks, corpus::log_corpus, scan, scan_compound, scan_entropy, scan_labeled, warm_up,
};

const SIZE: usize = 4 << 20;
const CHUNK: usize = 64 << 10;
const OVERLAP: usize = 8 << 10;
const DENSITIES: &[(&str, u64)] = &[("0pct", 0), ("1pct", 10), ("10pct", 100), ("50pct", 500)];

/// Chunk boundaries snapped to char boundaries (the corpus is ASCII anyway).
fn windows(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let end = (start + CHUNK).min(text.len());
        out.push(&text[start.saturating_sub(OVERLAP)..end]);
        start = end;
    }
    out
}

fn bench(c: &mut Criterion) {
    warm_up().expect("patterns compile");
    let mut group = c.benchmark_group("scan");
    group.sample_size(20);
    for &(name, density) in DENSITIES {
        let text = log_corpus(SIZE, density, 7);
        group.throughput(Throughput::Bytes(text.len() as u64));
        let mut out = Vec::new();
        group.bench_with_input(BenchmarkId::new("whole", name), &text, |b, t| {
            b.iter(|| scan(black_box(t), &mut out).map(|_| out.len()))
        });
        let wins = windows(&text);
        group.bench_with_input(BenchmarkId::new("windows", name), &wins, |b, ws| {
            b.iter(|| {
                let mut n = 0;
                for w in ws {
                    if scan(black_box(w), &mut out).is_ok() {
                        n += out.len();
                    }
                }
                n
            })
        });
        let mut labeled = Vec::new();
        group.bench_with_input(BenchmarkId::new("labeled", name), &text, |b, t| {
            b.iter(|| scan_labeled(black_box(t), &mut labeled).map(|_| labeled.len()))
        });
        let mut secrets = Vec::new();
        let ep = EntropyParams {
            min_length: 24,
            base64_entropy: 4.0,
            hex_entropy: 3.0,
        };
        group.bench_with_input(BenchmarkId::new("entropy", name), &text, |b, t| {
            b.iter(|| scan_entropy(black_box(t), ep, &mut secrets).map(|_| secrets.len()))
        });
        let cp = CompoundParams {
            min_length: 20,
            entropy_floor: 3.5,
            distinct_ratio: 0.45,
        };
        group.bench_with_input(BenchmarkId::new("compound", name), &text, |b, t| {
            b.iter(|| scan_compound(black_box(t), cp, &mut secrets).map(|_| secrets.len()))
        });
        group.bench_with_input(BenchmarkId::new("regex_only", name), &text, |b, t| {
            b.iter(|| bench_hooks::regex_only(black_box(t), &mut out).map(|_| out.len()))
        });
        group.bench_with_input(BenchmarkId::new("digits_only", name), &text, |b, t| {
            b.iter(|| bench_hooks::digits_only(black_box(t), &mut out).map(|_| out.len()))
        });
        group.bench_with_input(
            BenchmarkId::new("floor_count_lines", name),
            &text,
            |b, t| {
                b.iter(|| {
                    black_box(t)
                        .as_bytes()
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
