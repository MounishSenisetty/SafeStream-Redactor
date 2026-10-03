"""Throughput-only runs: every system, a fixed ~2 MB sample per corpus, 1 thread and all.

    python -m benchmarks.throughput --venv-root C:/Users/me/.safestream-bench/venvs

The accuracy harness (benchmarks/harness.py) pins every system to one thread so
per-core speed is like-for-like. That understates tools that use several cores
on one stream (Presidio's transformers engine via torch, ONNX Runtime via
intra-op threads), so this script reports both: each system at one thread and at
every logical CPU, on the same documents in the same order.

The sample is the corpus's dev documents in manifest order, cycled until it holds
``--sample-mb`` of UTF-8 text (small corpora repeat). A system that is still
running after ``--max-seconds`` stops at the next document boundary and its MB/s
is computed over what it processed; the row says so (``truncated``). Pass
``--max-seconds 0`` to always process the whole sample.

SafeStream's own multi-core path is processes (``--workers``), not threads, and
needs >= 8 MB ranges, so its "all threads" rows only differ for the ONNX tier
(ONNX Runtime intra-op threads). Process scaling is measured in Phase 3.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks import corpora, harness  # noqa: E402

CORPORA = ("presidio_research", "ai4privacy", "secrets", "redactionbench", "conll2003")


def sample(corpus: str, mb: float) -> list[str]:
    docs = [d.text for d in corpora.load(corpus, "dev").docs if d.text]
    out: list[str] = []
    size, i = 0, 0
    while docs and size < mb * 1e6:
        out.append(docs[i % len(docs)])
        size += len(out[-1].encode("utf-8"))
        i += 1
    return out


def _analyzer(system: str, threads: int) -> Any:
    _tier, kwargs = harness.SYSTEMS[system]
    harness.THREADS = threads  # Presidio's transformers engine reads it (torch threads)
    if kwargs is None:
        return harness._presidio(system)
    from safestream_redactor import Redactor
    from safestream_redactor.detectors.onnx_ner import OnnxPiiDetector

    redactor = Redactor(load_plugins=False, **kwargs)
    if kwargs.get("use_onnx"):  # rebuild the ONNX session with `threads` intra-op threads
        for i, det in enumerate(redactor._detectors):
            if isinstance(det, OnnxPiiDetector):
                redactor._detectors[i] = OnnxPiiDetector.from_files(
                    kwargs["onnx_model"],
                    kwargs["onnx_vocab"],
                    kwargs["onnx_labels"],
                    min_score=0.35,
                    batch_size=kwargs.get("onnx_batch_size", 1),
                    threads=threads,
                )

    def analyze(text: str) -> None:
        chunks = (text[i : i + 65536] for i in range(0, len(text), 65536))
        for _ in redactor.detect_stream(chunks):
            pass

    return analyze


def run_one(system: str, corpus: str, threads: int, mb: float, max_s: float) -> dict[str, Any]:
    texts = sample(corpus, mb)
    t0 = time.perf_counter()
    analyze = _analyzer(system, threads)
    analyze("Warm up: John Smith, john@example.com, 4111 1111 1111 1111.")
    load_s = time.perf_counter() - t0
    done_bytes, done_docs, latencies = 0, 0, []
    start = time.perf_counter()
    for text in texts:
        t = time.perf_counter()
        analyze(text)
        latencies.append(time.perf_counter() - t)
        done_bytes += len(text.encode("utf-8"))
        done_docs += 1
        if max_s and time.perf_counter() - start > max_s:
            break
    seconds = time.perf_counter() - start
    latencies.sort()
    return {
        "system": system,
        "corpus": corpus,
        "threads": threads,
        "sample_mb": round(sum(len(t.encode("utf-8")) for t in texts) / 1e6, 3),
        "processed_mb": round(done_bytes / 1e6, 4),
        "docs": done_docs,
        "truncated": done_docs < len(texts),
        "seconds": seconds,
        "mb_s": done_bytes / 1e6 / seconds if seconds else 0.0,
        "p50_ms": 1000 * latencies[len(latencies) // 2] if latencies else 0.0,
        "p99_ms": 1000 * latencies[min(len(latencies) - 1, int(0.99 * len(latencies)))]
        if latencies
        else 0.0,
        "load_s": load_s,
        "peak_rss_mb": harness._peak_rss_mb(),
        "power_at_end": harness._power(),
        "python": sys.executable,
        "versions": harness._versions(),
        "heavy_modules_loaded": sorted(m for m in harness._HEAVY if m in sys.modules),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--run-one", nargs=5, help=argparse.SUPPRESS)
    ap.add_argument("--corpora", nargs="+", default=list(CORPORA), choices=list(CORPORA))
    ap.add_argument("--systems", nargs="+", default=list(harness.SYSTEMS))
    ap.add_argument("--sample-mb", type=float, default=2.0)
    ap.add_argument("--max-seconds", type=float, default=120.0)
    ap.add_argument("--all-threads", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--venv-root", type=Path)
    ap.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=ROOT / "benchmarks" / "data" / "external" / "checkpoints" / "throughput",
    )
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--allow-battery", action="store_true")
    args = ap.parse_args()
    if args.run_one:
        system, corpus, threads, mb, max_s = args.run_one
        json.dump(run_one(system, corpus, int(threads), float(mb), float(max_s)), sys.stdout)
        return

    env = harness.environment()
    if env["power"] != "AC" and not env["power"].endswith("(AC)") and not args.allow_battery:
        ap.error(f"power is {env['power']}: throughput on battery is not comparable")
    args.checkpoint_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for corpus in args.corpora:
        for system in args.systems:
            for threads in sorted({1, args.all_threads}):
                ckpt = args.checkpoint_dir / f"{corpus}_{system}_t{threads}.json"
                if ckpt.exists():
                    saved = json.loads(ckpt.read_text(encoding="utf-8"))
                    if saved["commit"] == env["commit"] and not env["dirty"]:
                        rows.append(saved["row"])
                        print(f"# {corpus} {system} t{threads} (resumed)", file=sys.stderr)
                        continue
                print(f"# {corpus} {system} t{threads} ...", file=sys.stderr, flush=True)
                thread_env = {
                    k: str(threads)
                    for k in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS")
                }
                proc = subprocess.run(
                    [
                        harness._interpreter(system, args.venv_root),
                        "-m",
                        "benchmarks.throughput",
                        "--run-one",
                        system,
                        corpus,
                        str(threads),
                        str(args.sample_mb),
                        str(args.max_seconds),
                    ],
                    capture_output=True,
                    text=True,
                    cwd=ROOT,
                    encoding="utf-8",
                    errors="replace",
                    env={**os.environ, **thread_env, "PYTHONUTF8": "1"},
                )
                if proc.returncode != 0:
                    reason = (proc.stderr.strip().splitlines() or ["failed"])[-1]
                    print(f"#   failed: {reason}", file=sys.stderr)
                    rows.append(
                        {"system": system, "corpus": corpus, "threads": threads, "failed": reason}
                    )
                    continue
                row = json.loads(proc.stdout)
                rows.append(row)
                ckpt.write_text(json.dumps({"commit": env["commit"], "row": row}), encoding="utf-8")

    out = args.json or ROOT / "research" / "results" / "raw" / (
        f"{dt.date.today().isoformat()}_throughput.json"
    )
    out.write_text(
        json.dumps({"environment": env, "max_seconds": args.max_seconds, "rows": rows}, indent=1)
        + "\n",
        encoding="utf-8",
    )
    lines = [
        f"Throughput, {env['date']} | {env['cpu']} | power: {env['power']} | "
        f"{env['power_plan']} | commit {env['commit'][:10]}",
        "",
        "| Corpus | System | Threads | MB/s | p50 / p99 ms | Processed MB | Truncated "
        "| Peak RSS MB |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        if "failed" in r:
            lines.append(
                f"| {r['corpus']} | {r['system']} | {r['threads']} | failed: {r['failed']} ||||"
            )
            continue
        lines.append(
            f"| {r['corpus']} | {r['system']} | {r['threads']} | {r['mb_s']:.3g} | "
            f"{r['p50_ms']:.1f} / {r['p99_ms']:.1f} | "
            f"{r['processed_mb']:.3f} of {r['sample_mb']:.2f} | "
            f"{'yes' if r['truncated'] else 'no'} | {r['peak_rss_mb']:.0f} |"
        )
    table = "\n".join(lines) + "\n"
    print(table)
    (args.md or out.with_suffix(".md")).write_text(table, encoding="utf-8")
    print(f"# wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
