"""Peak RSS against input size: streaming redact_file vs whole-document redact.

    python benchmarks/memory_curve.py --out research/results/raw/memory_curve.json

Each point runs in a fresh process and reports that process's peak RSS
(``ru_maxrss``, so native-core allocations count, unlike tracemalloc) and its RSS
after imports, before any input is read. Streaming should stay flat as the input
grows (Theorem 3); whole-document ``redact()`` holds the input and output strings,
so it should grow with the input.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com logged in "
    "from 10.20.30.40 ref 4111-1111-1111-1111 ssn: 123-45-6789 key "
    "AKIAIOSFODNN7EXAMPLE ok\n"
)


def _child(mode: str, backend: str, path: str) -> None:
    import psutil

    from safestream_redactor import Redactor

    r = Redactor(backend=backend)
    r.redact("warm up bob@example.com")
    base = psutil.Process().memory_info().rss / 2**20
    t = time.perf_counter()
    if mode == "stream":
        r.redact_file(path, path + ".out")
    else:
        Path(path + ".out").write_text(r.redact(Path(path).read_text("utf-8")), "utf-8")
    secs = time.perf_counter() - t
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KiB on Linux
    print(json.dumps({"base_rss_mb": base, "peak_rss_mb": peak, "seconds": secs}))


def _write(path: Path, size_mb: int) -> None:
    block = (_LINE * 2048).encode()
    target, written = size_mb * 2**20, 0
    with path.open("wb") as f:
        while written < target:
            f.write(block)
            written += len(block)


def main() -> None:
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        _child(*sys.argv[2:])
        return
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--stream-sizes", type=int, nargs="+", default=[8, 32, 128, 512, 1024, 2048])
    ap.add_argument("--whole-sizes", type=int, nargs="+", default=[8, 32, 128, 256])
    ap.add_argument("--backends", nargs="+", default=["native", "python"])
    args = ap.parse_args()
    points = []
    with tempfile.TemporaryDirectory() as tmp:
        for mode, sizes in (("stream", args.stream_sizes), ("whole", args.whole_sizes)):
            for size in sizes:
                src = Path(tmp) / f"in_{size}.log"
                if not src.exists():
                    _write(src, size)
                for backend in args.backends:
                    proc = subprocess.run(
                        [sys.executable, __file__, "--child", mode, backend, str(src)],
                        capture_output=True, text=True, check=True,
                    )
                    row = {"mode": mode, "backend": backend, "size_mb": size,
                           **json.loads(proc.stdout.strip().splitlines()[-1])}
                    row["delta_mb"] = row["peak_rss_mb"] - row["base_rss_mb"]
                    points.append(row)
                    print(row, flush=True)
                    Path(str(src) + ".out").unlink(missing_ok=True)
                src.unlink()
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout
    args.out.write_text(json.dumps({
        "instrument": "ru_maxrss of a fresh process per point; base = RSS after imports",
        "python": platform.python_version(), "platform": platform.platform(),
        "cpu_count": os.cpu_count(), "commit": commit.strip(), "points": points,
    }, indent=1) + "\n")


if __name__ == "__main__":
    main()
