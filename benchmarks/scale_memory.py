"""Memory-vs-file-size scale curve substantiating Theorem 3 (WI-6).

Theorem 3 (docs/FORMAL_MODEL.md) claims peak working memory is bounded by
``chunk_size + overlap + L_max`` and is *independent of input size*. This script
redacts generated files across a range of sizes, records peak Python
allocations at each, and prints the curve — a flat line against a growing input
is the empirical proof of the constant-memory property.

It uses ``tracemalloc`` (Python-heap allocations), the same instrument as the
``memory``-marked test, so the numbers are comparable. Sizes are given in MB::

    python benchmarks/scale_memory.py --sizes 16 64 256 1024
    python benchmarks/scale_memory.py --sizes 16 64 256 --workers 4  # parallel path

The theorem is about *sequential* streaming; with ``--workers > 1`` the bound
scales by the worker count (Theorem 3, second clause), which the curve shows as
a higher but still flat line.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import tracemalloc

from safestream_redactor import Redactor

_LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com logged in "
    "from 10.20.30.40 ref 4111-1111-1111-1111 ssn: 123-45-6789 key "
    "AKIAIOSFODNN7EXAMPLE ok\n"
)


def _write_file(path: str, size_mb: int) -> None:
    block = _LINE * 2048  # ~256 KB per write
    block_bytes = len(block.encode())
    target = size_mb * 1024 * 1024
    with open(path, "w", encoding="utf-8") as f:
        written = 0
        while written < target:
            f.write(block)
            written += block_bytes


def measure(size_mb: int, *, workers: int, chunk_size: int, overlap: int) -> tuple[float, float]:
    """Return (peak_MB, throughput_MB_per_s) for redacting a ``size_mb`` file."""
    import time

    redactor = Redactor(chunk_size=chunk_size, overlap=overlap)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.log")
        dst = os.path.join(d, "out.log")
        _write_file(src, size_mb)
        actual_mb = os.path.getsize(src) / (1024 * 1024)

        tracemalloc.start()
        start = time.perf_counter()
        redactor.redact_file(src, dst, workers=workers)
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return peak / (1024 * 1024), actual_mb / elapsed if elapsed else float("inf")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--sizes", type=int, nargs="+", default=[16, 64, 256], help="file sizes in MB")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--chunk-size", type=int, default=64 * 1024)
    ap.add_argument("--overlap", type=int, default=8 * 1024)
    args = ap.parse_args()

    print(f"workers={args.workers} chunk_size={args.chunk_size} overlap={args.overlap}")
    print(
        f"(sequential buffer bound ~= chunk_size+overlap+L_max, x{max(1, args.workers)} parallel)\n"
    )
    print(f"{'size (MB)':>12}{'peak (MB)':>12}{'MB/s':>10}")
    peaks = []
    for size_mb in args.sizes:
        peak_mb, throughput = measure(
            size_mb, workers=args.workers, chunk_size=args.chunk_size, overlap=args.overlap
        )
        peaks.append(peak_mb)
        print(f"{size_mb:>12}{peak_mb:>12.2f}{throughput:>10.1f}")

    spread = max(peaks) - min(peaks)
    print(
        f"\npeak spread across a {min(args.sizes)}->{max(args.sizes)} MB range: "
        f"{spread:.2f} MB — flat means memory is independent of input size (Theorem 3)."
    )


if __name__ == "__main__":
    main()
