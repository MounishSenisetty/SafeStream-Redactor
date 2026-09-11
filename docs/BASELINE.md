# Performance baseline (Phase 2)

The reference every later optimization is measured against. Reproduce with
`benchmarks/baseline.py` (see below). Numbers are from **one specific, shared,
loaded environment** — treat the *ratios and shapes* as the durable result and
re-run the harness on your target host for absolute figures.

## Environment

| | |
| --- | --- |
| CPU | Intel Xeon @ 2.10 GHz, 4 vCPU (shared dev container) |
| Python | 3.11.15, x86_64, CPython |
| Package | `safestream_redactor` @ `main` (post PR #32), `load_plugins=False` |
| Method | file→file `redact_file`; page cache hot; timed pass has **no** tracemalloc |

Corpora are generated deterministically by the harness. A "PII line" carries one
synthetic specimen (email / IPv4 / SSN / credit-card / phone / AWS key / GitHub
token / JWT); a "distractor line" is a realistic timestamped log line with numbers
but no PII (and, by construction, no 20+ char high-entropy run). **Density = the
fraction of PII-bearing lines.** No real PII is used or printed.

## Result 1 — throughput & memory vs PII density (10 MB, single core)

| Density | Throughput | Read-only (I/O) | I/O : detect | Detections | Peak heap | Self RSS |
| --- | --- | --- | --- | --- | --- | --- |
| none (0%)   | **4.27 MB/s** | ~5150 MB/s | ~1200× | 0       | 0.46 MB | 20.3 MB |
| low (1%)    | **3.48 MB/s** | ~5180 MB/s | ~1490× | 929     | 0.54 MB | 20.4 MB |
| medium (10%)| **3.20 MB/s** | ~4510 MB/s | ~1410× | 10 202  | 0.62 MB | 20.5 MB |
| high (50%)  | **2.71 MB/s** | ~4490 MB/s | ~1660× | 69 594  | 1.14 MB | 21.2 MB |

Reading it:

- **CPU-bound on detection, confirmed.** End-to-end throughput is 2.7–4.3 MB/s
  while the pure read+decode layer is ~4.5–5.2 GB/s — input I/O is **~1200–1660×
  faster** than redaction. Optimizing I/O cannot move the total (see
  `docs/ZERO_COPY.md`).
- **Throughput falls as PII density rises** (4.27 → 2.71 MB/s): each real match
  runs the full regex/validator/arbitration/replace path; the anchor prefilter
  makes the 0%-density fast path the quickest.
- **Memory is flat and tiny** regardless of density: peak Python heap ≤ ~1.1 MB
  and RSS ~20 MB (interpreter baseline), independent of input size — the
  constant-memory invariant (`tests/test_memory.py`, `docs/FORMAL_MODEL.md` Thm 3).

## Result 2 — core scaling (67 MB, medium density, intra-file parallel)

| Workers | Throughput | Speedup | Cores used | Detections | Worker RSS |
| --- | --- | --- | --- | --- | --- |
| 1 | 3.05 MB/s  | 1.00×  | 1.00 | 63 607 | — |
| 2 | 5.47 MB/s  | 1.79×  | 1.84 | 63 607 | 16.6 MB |
| 4 | 11.20 MB/s | 3.67×  | 3.70 | 63 607 | 16.8 MB |

Reading it:

- **~3.67× on 4 cores** — near-linear; "cores used" (CPU-time / wall-time) tracks
  worker count, so the work is genuinely parallel, not I/O-stalled.
- **Detections are identical across worker counts** (63 607), corroborating the
  parallel-path byte-identity guarantee (`docs/FORMAL_MODEL.md` Thm 2).
- **Memory scales with workers, not file size**: each worker ~17 MB RSS; total ≈
  workers × per-worker, bounded (`redact_file(..., workers=N)`).

## The headline number this establishes

**Single-core ≈ 3 MB/s (density-dependent 2.7–4.3); 4-core ≈ 11 MB/s.** This is
the ceiling the native-core work (see `docs/PERF_ASSESSMENT.md`) must beat, and
the figure every future change is compared against. The detection tier — not I/O,
memory, or copies — is the thing to make faster.

## What is *not* the bottleneck (measured)

Input read/decode (~4.5–5.2 GB/s), memory (flat ~20 MB), allocations (≤1.1 MB peak
heap). These confirm the assessment: `io_uring`/`mmap`/zero-copy/SIMD-in-Python
target non-bottleneck layers here.

## Reproducing

```bash
# throughput + memory across densities (per-size, sequential)
python benchmarks/baseline.py --sizes 10 --densities none low medium high

# core scaling (needs >=~16 MB to split; 64 MB gives up to 8 ranges)
python benchmarks/baseline.py --sizes 64 --densities medium --workers 1 2 4 --no-heap

# larger inputs / machine-readable output
python benchmarks/baseline.py --sizes 100 1000 --densities medium --json baseline.json
```

Each configuration runs in its own subprocess so peak RSS and peak heap are
isolated; the timed pass excludes tracemalloc; corpora are seeded for repeatability.
Larger sizes (1 GB, 10 GB) are supported via `--sizes` and confirm flat memory; they
are omitted from this recorded run only for wall-clock reasons, not capability.
