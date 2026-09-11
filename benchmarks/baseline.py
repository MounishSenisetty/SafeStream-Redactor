"""Baseline performance harness — the reference every optimization is measured against.

Establishes Phase-2 baselines for SafeStream-Redactor's file-to-file redaction:
throughput, peak RSS, peak Python heap (allocations), CPU utilization (cores
used), and core-scaling, across input sizes and PII densities. It also times a
pure input-read pass so the I/O-vs-detection split is explicit.

Design notes (why it measures what it measures):
- **Each configuration runs in its own subprocess** (``--run-one``), so peak RSS
  (``getrusage``) and peak Python heap (``tracemalloc``) are isolated per config
  rather than accumulating a process-wide high-water mark.
- **Corpora are generated deterministically** (seeded) and reused across worker
  counts, so results are repeatable and comparable.
- **No PII is ever printed** — only counts, sizes, and timings. The generated
  values are synthetic specimens, never real data.
- Peak RSS for parallel runs is reported for both the orchestrator (self) and the
  largest worker (children); parallel total memory is approx workers x per-worker.
- **Throughput and peak-heap are measured in separate passes**: tracemalloc adds
  large overhead, so the timed pass runs without it and the heap pass (optional,
  --no-heap to skip on huge inputs) runs untimed.

Usage:
    # throughput + memory across densities (10 MB each, sequential)
    python benchmarks/baseline.py --sizes 10 --densities none low medium high

    # core-scaling (needs >=~16 MB to split; 64 MB gives up to 8 ranges)
    python benchmarks/baseline.py --sizes 64 --densities medium --workers 1 2 4

    # record machine-readable results
    python benchmarks/baseline.py --sizes 10 100 --densities none low high --json out.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import random
import resource
import subprocess
import sys
import tempfile
import time
import tracemalloc
from dataclasses import asdict, dataclass

# --- deterministic synthetic corpus generation -------------------------------
#
# A "PII line" carries exactly one synthetic specimen; a "distractor line" is a
# realistic log line with a timestamp and numbers but no PII (so the digit-gated
# detectors' prefilter is exercised even at 0% density, as in real logs). Density
# = fraction of PII-bearing lines.

_PII_SPECIMENS = (
    "user bob.smith{n}@corp.example.com logged in",
    "client ip 10.20.{a}.{b} connected",
    "card 4111 1111 1111 1111 charged",  # valid Luhn
    "ssn 123-45-6789 on file",
    "call +1 (415) 555-0{n:03d} back",
    "key AKIAIOSFODNN7EXAMPLE rotated",
    "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 used",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0",
)
# Realistic log line with a timestamp and numbers (so the digit-gated detectors'
# prefilter is exercised) but deliberately no run of 20+ secret-class characters,
# so the entropy tier does not flag it — "none" density then means ~0 detections.
_DISTRACTOR = (
    "2024-01-{d:02d}T00:00:{s:02d}Z INFO req {r:04x} latency {lat}ms "
    "status 200 path /api/v1/users id {rid} cache hit bytes {by}"
)

_DENSITIES = {"none": 0.0, "low": 0.01, "medium": 0.10, "high": 0.50}


def _gen_line(rng: random.Random, is_pii: bool) -> str:
    if is_pii:
        spec = rng.choice(_PII_SPECIMENS)
        return spec.format(n=rng.randint(0, 999), a=rng.randint(0, 255), b=rng.randint(1, 254))
    return _DISTRACTOR.format(
        d=rng.randint(1, 28),
        s=rng.randint(0, 59),
        r=rng.randint(0, 0xFFFFFF),
        lat=rng.randint(1, 900),
        rid=rng.randint(1000, 999999),
        by=rng.randint(10, 100000),
    )


def generate(path: str, size_mb: int, density: str, seed: int = 1234) -> None:
    """Write a ~``size_mb`` MB corpus with the given PII density, deterministically."""
    p = _DENSITIES[density]
    rng = random.Random(seed)
    target = size_mb * 1024 * 1024
    written = 0
    buf: list[str] = []
    with open(path, "w", encoding="utf-8") as f:
        while written < target:
            for _ in range(4096):
                line = _gen_line(rng, rng.random() < p) + "\n"
                buf.append(line)
                written += len(line.encode())
            block = "".join(buf)
            f.write(block)
            buf.clear()
            if written >= target:
                break


# --- measurement (runs in a subprocess, one config) --------------------------


@dataclass(slots=True)
class Result:
    size_mb: float
    density: str
    workers: int
    wall_s: float
    read_only_wall_s: float
    throughput_mb_s: float
    read_throughput_mb_s: float
    detections: int
    peak_heap_mb: float  # tracemalloc peak (main process)
    self_rss_mb: float  # orchestrator peak RSS
    child_rss_mb: float  # largest worker peak RSS (0 if sequential)
    cpu_s: float  # user+sys, self+children
    cores_used: float  # cpu_s / wall_s
    fell_back: bool


def _rss_mb(ru: resource.struct_rusage) -> float:
    # ru_maxrss is KB on Linux, bytes on macOS
    kb = ru.ru_maxrss if sys.platform.startswith("linux") else ru.ru_maxrss / 1024
    return kb / 1024


def _redact(redactor: object, path: str, out: str, workers: int) -> tuple[int, bool]:
    """Run one redaction; return (detections, fell_back)."""
    if workers > 1:
        from safestream_redactor.parallel import redact_file_parallel

        outcome = redact_file_parallel(redactor, path, out, workers=workers)  # type: ignore[arg-type]
        return outcome.stats.total, outcome.fell_back
    stats = redactor.redact_file(path, out)  # type: ignore[attr-defined]
    return stats.total, False


def run_one(path: str, workers: int, *, heap: bool = True) -> Result:
    from safestream_redactor import Redactor
    from safestream_redactor.engine import read_chunks

    size = os.path.getsize(path)
    out = path + ".redacted"

    # warm the page cache and time a pure read+decode pass (I/O reference)
    for _ in read_chunks(path, 64 * 1024):
        pass
    t0 = time.perf_counter()
    for _ in read_chunks(path, 64 * 1024):
        pass
    read_wall = time.perf_counter() - t0

    redactor = Redactor(load_plugins=False)
    # Timed pass — NO tracemalloc (its overhead would corrupt the throughput).
    t0 = time.perf_counter()
    detections, fell_back = _redact(redactor, path, out, workers)
    wall = time.perf_counter() - t0

    # Capture RSS/CPU now, before the (untimed) heap pass inflates them.
    self_ru = resource.getrusage(resource.RUSAGE_SELF)
    child_ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = self_ru.ru_utime + self_ru.ru_stime + child_ru.ru_utime + child_ru.ru_stime

    # Separate untimed pass to measure peak Python heap without skewing timing.
    peak_heap = 0
    if heap:
        tracemalloc.start()
        _redact(redactor, path, out, workers)
        _, peak_heap = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    with contextlib.suppress(OSError):
        os.unlink(out)

    mb = size / 1e6
    return Result(
        size_mb=round(mb, 1),
        density="?",  # filled by caller
        workers=workers,
        wall_s=round(wall, 3),
        read_only_wall_s=round(read_wall, 4),
        throughput_mb_s=round(mb / wall, 3),
        read_throughput_mb_s=round(mb / read_wall, 1),
        detections=detections,
        peak_heap_mb=round(peak_heap / 1e6, 2),
        self_rss_mb=round(_rss_mb(self_ru), 1),
        child_rss_mb=round(_rss_mb(child_ru), 1),
        cpu_s=round(cpu, 3),
        cores_used=round(cpu / wall, 2),
        fell_back=fell_back,
    )


# --- driver ------------------------------------------------------------------


def _run_child(path: str, workers: int, density: str, *, heap: bool) -> Result:
    cmd = [sys.executable, __file__, "--run-one", "--path", path, "--workers", str(workers)]
    if not heap:
        cmd.append("--no-heap")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    data["density"] = density
    return Result(**data)


def _print_table(results: list[Result]) -> None:
    hdr = (
        f"{'size':>6} {'density':>7} {'wkrs':>4} {'MB/s':>8} {'read MB/s':>10} "
        f"{'cores':>5} {'heap MB':>8} {'selfRSS':>8} {'childRSS':>8} {'dets':>10} {'fb':>3}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in results:
        print(
            f"{r.size_mb:>5}M {r.density:>7} {r.workers:>4} {r.throughput_mb_s:>8.2f} "
            f"{r.read_throughput_mb_s:>10.0f} {r.cores_used:>5.2f} {r.peak_heap_mb:>8.2f} "
            f"{r.self_rss_mb:>8.1f} {r.child_rss_mb:>8.1f} {r.detections:>10} "
            f"{'Y' if r.fell_back else '-':>3}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-one", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--path", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--sizes", type=int, nargs="+", default=[10], metavar="MB")
    ap.add_argument(
        "--densities",
        nargs="+",
        default=["none", "low", "medium", "high"],
        choices=list(_DENSITIES),
    )
    ap.add_argument("--workers", type=int, nargs="+", default=[1])
    ap.add_argument(
        "--no-heap", dest="heap", action="store_false", help="skip the tracemalloc pass"
    )
    ap.add_argument("--json", default=None, metavar="FILE", help="write results as JSON")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    if args.run_one:
        # measured child: one redaction of --path at --workers, JSON to stdout
        res = run_one(args.path, args.workers[0] if args.workers else 1, heap=args.heap)
        print(json.dumps(asdict(res)))
        return

    results: list[Result] = []
    tmp = tempfile.mkdtemp(prefix="safestream-baseline.")
    try:
        for size in args.sizes:
            for density in args.densities:
                path = os.path.join(tmp, f"corpus-{size}-{density}.log")
                print(f"# generating {size} MB, density={density} ...", file=sys.stderr)
                generate(path, size, density, seed=args.seed)
                for w in args.workers:
                    print(f"#   run size={size} density={density} workers={w}", file=sys.stderr)
                    results.append(_run_child(path, w, density, heap=args.heap))
                os.unlink(path)
    finally:
        with contextlib.suppress(OSError):
            os.rmdir(tmp)

    print()
    _print_table(results)
    if args.json:
        payload = {"platform": sys.platform, "results": [asdict(r) for r in results]}
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\n-- wrote {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
