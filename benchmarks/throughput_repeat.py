"""Throughput, repeated: N runs per cell, reported as mean and sample standard deviation.

    python benchmarks/throughput_repeat.py --runs 5 --venv-root ~/bench-venvs \\
        --out research/results/raw/throughput_repeat.json

Part A, real corpora (test splits), one thread: each run is a fresh
``harness --run-one`` process; MB/s = corpus bytes / summed per-document analysis
time (load excluded). gitleaks and TruffleHog are batch CLIs, so their figure is
one whole run including process start-up.

Part B, one large file: ``redact_file`` on a seeded synthetic log
(``tiered_bench.generate``: mostly innocent log lines and prose with PII and
secrets mixed in) at each worker count. Run on an otherwise idle machine.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks import harness  # noqa: E402

SYSTEMS_A = [
    "safestream-native",
    "safestream-python",
    "safestream-native-spacy",
    "presidio-regex",
    "presidio-sm",
    "presidio-lg",
    "gitleaks",
    "trufflehog",
]
CORPORA_A = ["presidio_research", "secrets", "redactionbench"]


def _summary(xs: list[float]) -> dict[str, float | list[float]]:
    return {
        "mean": statistics.mean(xs),
        "sd": statistics.stdev(xs) if len(xs) > 1 else 0.0,
        "runs": xs,
    }


def _large_file(workers: int, backend: str, path: Path) -> float:
    code = (
        "import sys,time;from safestream_redactor import Redactor;"
        f"r=Redactor(backend='{backend}');t=time.perf_counter();"
        f"r.redact_file(r'{path}', r'{path}.out', workers={workers});"
        "print(time.perf_counter()-t)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    return path.stat().st_size / 1e6 / float(out.stdout.strip().splitlines()[-1])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--venv-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--size-mb", type=float, default=256)
    ap.add_argument("--python-size-mb", type=float, default=32)
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4])
    args = ap.parse_args()

    env = {**os.environ, **harness._THREAD_ENV, "PYTHONUTF8": "1"}
    part_a: dict[str, dict[str, object]] = {}
    for corpus in CORPORA_A:
        for system in SYSTEMS_A:
            rates = []
            for _ in range(args.runs):
                proc = subprocess.run(
                    [
                        harness._interpreter(system, args.venv_root),
                        "-m",
                        "benchmarks.harness",
                        "--run-one",
                        system,
                        corpus,
                        "test",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=ROOT,
                    env=env,
                    check=True,
                )
                run = json.loads(proc.stdout)
                rates.append(run["bytes"] / 1e6 / sum(run["per_doc_s"]))
            part_a[f"{corpus}/{system}"] = _summary(rates)
            print(corpus, system, part_a[f"{corpus}/{system}"], flush=True)

    from benchmarks.tiered_bench import generate

    part_b: dict[str, object] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for backend, size in (("native", args.size_mb), ("python", args.python_size_mb)):
            path = Path(tmp) / f"bench_{backend}.txt"
            generate(path, size)
            for w in args.workers:
                rates = [_large_file(w, backend, path) for _ in range(args.runs)]
                part_b[f"{backend}/workers={w}"] = {
                    "file_mb": path.stat().st_size / 1e6,
                    **_summary(rates),
                }
                print(backend, w, part_b[f"{backend}/workers={w}"], flush=True)

    env_block = harness.environment()
    args.out.write_text(
        json.dumps(
            {
                "runs": args.runs,
                "environment": env_block,
                "load_avg_at_end": os.getloadavg(),
                "python": platform.python_version(),
                "part_a_test_splits_1_thread": part_a,
                "part_b_large_file": part_b,
                "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            },
            indent=1,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
