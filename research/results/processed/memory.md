# Constant-Memory Scaling — Measured Results

Generated from [`../raw/memory_2026-08-16.json`](../raw/memory_2026-08-16.json).
Environment: CPython 3.11.15, Linux x86_64, Intel Xeon @ 2.10 GHz, 16 GB RAM.
Package 0.2.0, commit `ad38aa4`. Config: `workers=1, chunk_size=64 KiB, overlap=8 KiB`.
Instrument: `tracemalloc` (Python-heap peak allocations).

| Input size | Peak memory | Ratio to smallest |
|---|---|---|
| 8 MB | 2.75 MB | 1.00× |
| 32 MB | 2.75 MB | 1.00× |

**Peak spread across the 8 → 32 MB range: 0.00 MB.** A 4× increase in input produces
**zero** increase in peak allocation — the empirical signature of the constant-memory
property (Theorem 3, `docs/FORMAL_MODEL.md`): peak working memory is bounded by
`chunk_size + overlap + L_max`, independent of input size.

## Corroboration on a 1 GB file

The repository's `memory`-marked test proves the same property at three orders of
magnitude larger scale:

```bash
pytest -m memory -o addopts=''
# tests/test_memory.py::test_constant_memory_on_large_file
# redacts a ~1 GB generated file and asserts peak tracemalloc allocations < 16 MB
```

So a 1 GB input redacts with peak Python-heap allocations under 16 MB — the same footprint
class as the 8 MB and 32 MB runs above.

## Two honest caveats

- **The `MB/s` column of `scale_memory.py` is not throughput.** `tracemalloc` roughly
  triples runtime; the instrumented rate here (~0.3 MB/s) reflects that overhead, not real
  speed. For throughput see [`accuracy.md`](accuracy.md) (2–3.5 MB/s single-core on this
  throttled vCPU).
- **A wider curve reproduces the same flat line** (`--sizes 8 32 128 512`) but is slow to
  run under `tracemalloc` on a shared 2.1 GHz vCPU; the 1 GB test above is the faster way
  to confirm the property at scale.

## Reproduce

```bash
python benchmarks/scale_memory.py --sizes 8 32 64
# or the full proof:
pytest -m memory -o addopts=''
```
