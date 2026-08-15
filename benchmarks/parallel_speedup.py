"""Parallel speedup and byte-identity check substantiating Theorem 2 (WI-8).

Theorem 2 (docs/FORMAL_MODEL.md) claims the parallel engine's output is
byte-identical to the sequential engine's (falling back to sequential when it
cannot guarantee that). This script redacts one generated file at a range of
worker counts, and for each:

- times it and reports speedup vs. the 1-worker sequential baseline;
- hashes the output and asserts it equals the sequential output byte-for-byte —
  the empirical confirmation of the guarantee, run across every worker count.

If any worker count produces different bytes, the script exits non-zero: a
regression in the seam protocol would be caught here.

    python benchmarks/parallel_speedup.py --size 256 --workers 1 2 4 8
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import time

from safestream_redactor import Redactor

_LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com from 10.20.30.40 "
    "card 4111-1111-1111-1111 ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE "
    "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 tail\n"
)


def _write_file(path: str, size_mb: int) -> None:
    block = _LINE * 2048
    block_bytes = len(block.encode())
    target = size_mb * 1024 * 1024
    with open(path, "w", encoding="utf-8") as f:
        written = 0
        while written < target:
            f.write(block)
            written += block_bytes


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--size", type=int, default=128, help="file size in MB")
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    ap.add_argument("--overlap", type=int, default=8 * 1024)
    args = ap.parse_args()

    redactor = Redactor(overlap=args.overlap)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.log")
        _write_file(src, args.size)
        actual_mb = os.path.getsize(src) / (1024 * 1024)
        print(f"file: {actual_mb:.1f} MB, overlap={args.overlap}\n")

        baseline_digest: str | None = None
        baseline_time: float | None = None
        print(f"{'workers':>8}{'time (s)':>12}{'MB/s':>10}{'speedup':>10}{'byte-identical':>16}")
        ok = True
        for w in args.workers:
            dst = os.path.join(d, f"out.{w}.log")
            start = time.perf_counter()
            redactor.redact_file(src, dst, workers=w)
            elapsed = time.perf_counter() - start
            digest = _sha256(dst)
            if baseline_digest is None:
                baseline_digest, baseline_time = digest, elapsed
                identical = "(baseline)"
            else:
                identical = "yes" if digest == baseline_digest else "NO — MISMATCH"
                ok = ok and digest == baseline_digest
            speedup = (baseline_time / elapsed) if baseline_time and elapsed else 0.0
            mbps = actual_mb / elapsed
            print(f"{w:>8}{elapsed:>12.2f}{mbps:>10.1f}{speedup:>9.2f}x{identical:>16}")
            os.unlink(dst)

    if not ok:
        print("\nFAIL: a parallel run diverged from the sequential output.")
        return 1
    print("\nOK: every worker count produced byte-identical output (Theorem 2).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
