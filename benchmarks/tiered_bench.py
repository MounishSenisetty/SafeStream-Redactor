"""Tiered pipeline benchmark: Tier-0 (native) vs Tier-0 + gated Tier-2 (ONNX NER).

Generates ``bench_data.txt``, a seeded synthetic stream of mostly innocent log
lines with innocent prose, structured PII, secrets and person names mixed in, and
remembers where every sensitive value is (gold spans). Then:

* **Recall**, strict: an entity counts only if *every* character of it is inside a
  detection (a half-redacted key is a leaked key). Reported separately for
  (a) structured PII + secrets and (b) person names. Detections come from the
  streaming engine (``detect_stream``), exactly as ``redact_file`` sees them.
* **Throughput** (MB/s) of real ``redact_file`` runs at each ``--workers`` count.
* **Latency** per 64 KiB window (p50 / p99 of ``Redactor.detect``), one process.

Synthetic data is the easy case: values are canonical and names appear in clean
sentences. Use RedactionBench (benchmarks/redactionbench/) for an independent,
harder name-recall number.

Usage:
    python benchmarks/tiered_bench.py --model models/ner --workers 1 4 8 16
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import statistics
import string
import sys
import tempfile
import time
import warnings
from pathlib import Path

from safestream_redactor import parallel

LOGS = (
    "2024-03-{d:02d}T{h:02d}:{m:02d}:{s:02d}Z INFO req {r:06x} latency {n}ms status 200 "
    "path /api/v1/items id {k} cache hit",
    "GET /healthz 200 {n}ms upstream=10.0.{d}.{h}:8080 bytes={k} cache=MISS",
    "worker-{d} job {r:08x} done in {n}ms queue=default retries=0",
)
PROSE = (
    "The nightly backup finished without errors.",
    "Rollback is not required; Monitoring shows normal traffic.",
    "Quarterly Report attached for Review by Finance.",
    "Release notes: Improved caching and Faster startup on Windows.",
)
FIRST = (
    "Maria", "Wei", "Priya", "Olusegun", "Siobhan", "José", "Kwame", "Aiko", "Dmitri",
    "Fatima", "Liam", "Ngozi", "Hiroshi", "Ananya", "Mateo", "Zainab", "Lars", "Mei",
    "Rahul", "Chloe", "Tomasz", "Amara", "Yusuf", "Ingrid", "Diego", "Sakura", "Emeka",
    "Leila", "Bjorn", "Thandiwe",
)  # fmt: skip
LAST = (
    "Gonzalez", "Zhang", "Ramanathan", "Obasanjo", "O'Neill", "García", "Mensah", "Tanaka",
    "Volkov", "Haddad", "Murphy", "Okafor", "Watanabe", "Iyer", "Rossi", "Abubakar",
    "Lindqvist", "Chen", "Kapoor", "Dubois", "Kowalski", "Diallo", "Demir", "Andersen",
    "Fernández", "Kobayashi", "Eze", "Karimi", "Nilsen", "Dlamini",
)  # fmt: skip
NAME_TEMPLATES = (
    "Patient {v} was admitted for observation.",
    "Signed by {v} on behalf of the board.",
    "Contact: {v}",
    "Dr. {v} reviewed the chart.",
    "{v} approved the change request.",
    "Meeting with {v} moved to Friday.",
    "Dear {v}, your order has shipped.",
)

_ALNUM = string.ascii_letters + string.digits


def _rand(rng: random.Random, n: int, alphabet: str = _ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _luhn(rng: random.Random, prefix: str, length: int) -> str:
    body = prefix + "".join(rng.choice(string.digits) for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch) * (2 if i % 2 == 0 else 1)
        total += d - 9 if d > 9 else d
    return body + str((10 - total % 10) % 10)


def _b64(rng: random.Random, n: int) -> str:
    return base64.urlsafe_b64encode(rng.randbytes(n)).decode().rstrip("=")


def _structured(rng: random.Random) -> tuple[str, str, str]:
    """(entity type, line template with {v}, value)."""
    kind = rng.randrange(12)
    if kind == 0:
        area = rng.choice([n for n in range(1, 900) if n != 666])
        v = f"{area:03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"
        return "ssn", "employee ssn {v} on file", v
    if kind == 1:
        user = f"{rng.choice(FIRST).lower()}.{_rand(rng, 5, string.ascii_lowercase)}"
        return "email", "notify {v} on failure", f"{user}@corp-{rng.randint(1, 99)}.io"
    if kind == 2:
        v = " ".join(
            _luhn(rng, rng.choice(["4", "51", "55"]), 16)[i : i + 4] for i in (0, 4, 8, 12)
        )
        return "credit_card", "card {v} charged", v
    if kind == 3:
        return (
            "phone",
            "call {v} back",
            f"+1 ({rng.randint(201, 989)}) 555-01{rng.randint(0, 99):02d}",
        )
    if kind == 4:
        v = ".".join(
            str(rng.randint(lo, hi)) for lo, hi in ((11, 223), (0, 255), (0, 255), (1, 254))
        )
        return "ipv4", "client ip {v} connected", v
    if kind == 5:
        return (
            "aws_key",
            "rotating {v} now",
            "AKIA" + _rand(rng, 16, string.ascii_uppercase + string.digits),
        )
    if kind == 6:
        return "github_token", "GH token {v}", "ghp_" + _rand(rng, 36)
    if kind == 7:
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
        v = f"{header}.{_b64(rng, 48)}.{_b64(rng, 32)}"
        return "jwt", "Authorization: Bearer {v}", v
    if kind == 8:
        return "api_key", "api_key={v}", _rand(rng, 24)
    if kind == 9:
        return "secret", "deploying with {v} in prod", _rand(rng, 32)
    if kind == 10:
        return "anthropic_key", "ANTHROPIC_API_KEY={v}", "sk-ant-api03-" + _rand(rng, 40)
    body = "\n".join(base64.b64encode(rng.randbytes(48)).decode() for _ in range(4))
    v = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    return "private_key", "key:\n{v}", v


def generate(path: Path, size_mb: float, seed: int = 7) -> list[tuple[int, int, str, str]]:
    """Write the corpus; return gold ``(start, end, category, type)`` in characters."""
    rng = random.Random(seed)
    gold: list[tuple[int, int, str, str]] = []
    pos, written, target = 0, 0, int(size_mb * 1e6)
    with open(path, "w", encoding="utf-8", newline="") as f:
        while written < target:
            roll = rng.random()
            if roll < 0.80:
                line = rng.choice(LOGS).format(
                    d=rng.randint(1, 28), h=rng.randint(0, 23), m=rng.randint(0, 59),
                    s=rng.randint(0, 59), r=rng.getrandbits(32), n=rng.randint(1, 900),
                    k=rng.randint(1000, 99999),
                )  # fmt: skip
            elif roll < 0.88:
                line = rng.choice(PROSE)
            else:
                if roll < 0.94:
                    etype, template, value = _structured(rng)
                    category = "structured"
                else:
                    etype, category = "person", "person"
                    template = rng.choice(NAME_TEMPLATES)
                    value = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
                line = template.format(v=value)
                start = pos + line.index(value)
                gold.append((start, start + len(value), category, etype))
            line += "\n"
            f.write(line)
            pos += len(line)
            written += len(line.encode())
    return gold


def recall(redactor: object, path: Path, gold: list[tuple[int, int, str, str]]) -> dict:
    from safestream_redactor.engine import read_chunks

    covered: list[tuple[int, int]] = []
    offset = 0
    for segment, dets in redactor.detect_stream(read_chunks(str(path), 64 * 1024)):
        covered.extend((offset + d.start, offset + d.end) for d in dets)
        offset += len(segment)
    covered.sort()
    # merge touching detections into maximal covered intervals
    merged: list[list[int]] = []
    for s, e in covered:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    starts = [m[0] for m in merged]
    from bisect import bisect_right

    stats: dict[str, dict[str, list[int]]] = {"structured": {}, "person": {}}
    for s, e, cat, etype in gold:
        i = bisect_right(starts, s) - 1
        hit = i >= 0 and merged[i][0] <= s and merged[i][1] >= e
        row = stats[cat].setdefault(etype, [0, 0])
        row[0] += hit
        row[1] += 1
    out: dict = {}
    for cat, by_type in stats.items():
        found = sum(v[0] for v in by_type.values())
        total = sum(v[1] for v in by_type.values())
        out[cat] = {
            "recall": round(found / total, 5) if total else None,
            "found": found,
            "total": total,
            "by_type": {t: round(v[0] / v[1], 4) for t, v in sorted(by_type.items())},
        }
    return out


def latency(redactor: object, path: Path, windows: int = 200) -> dict:
    text = path.read_text(encoding="utf-8")
    step = 64 * 1024
    times = []
    for i in range(0, min(len(text), windows * step), step):
        t = time.perf_counter()
        redactor.detect(text[i : i + step + 8 * 1024])
        times.append((time.perf_counter() - t) * 1e3)
    q = statistics.quantiles(times, n=100)
    return {"p50_ms": round(q[49], 2), "p99_ms": round(q[98], 2), "windows": len(times)}


def throughput(redactor: object, path: Path, workers: int) -> float:
    out = str(path) + ".out"
    t = time.perf_counter()
    redactor.redact_file(path, out, workers=workers)
    dt = time.perf_counter() - t
    os.unlink(out)
    return round(path.stat().st_size / 1e6 / dt, 2)


def build(config: str, model: Path | None) -> object:
    from safestream_redactor import Redactor

    if config == "t0":
        return Redactor(backend="native")
    assert model is not None
    return Redactor(
        backend="native",
        use_onnx=True,
        onnx_model=str(model / "model.int8.onnx"),
        onnx_vocab=str(model / "tokenizer.json"),
        onnx_labels=str(model / "labels.json"),
    )


def main() -> None:
    warnings.simplefilter("ignore", RuntimeWarning)
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", type=Path, default=Path("models/ner"))
    ap.add_argument("--workers", type=int, nargs="+", default=[1, 4, 8, 16])
    ap.add_argument("--size-mb", type=float, default=256, help="Tier-0 throughput corpus")
    ap.add_argument("--ner-size-mb", type=float, default=2, help="Tier-0+2 corpus for one worker")
    ap.add_argument("--recall-mb", type=float, default=4, help="recall/latency corpus")
    ap.add_argument("--data", type=Path, default=Path(tempfile.gettempdir()) / "bench_data.txt")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    configs = ["t0"]
    if (args.model / "model.int8.onnx").exists():
        configs.append("t0_t2")
    else:
        print(f"# no model at {args.model}; skipping Tier-2 (run scripts/export_onnx.py)")
    results: dict = {"platform": sys.platform, "cpu_count": os.cpu_count(), "configs": {}}

    gold = generate(args.data, args.recall_mb)
    from safestream_redactor.detectors.onnx_ner import _candidate_windows

    sample = args.data.read_text(encoding="utf-8")
    # share of the input's characters the model reads (windows, not whole lines)
    windows = _candidate_windows(sample)
    results["model_input_fraction"] = round(sum(len(w) for _, w in windows) / len(sample), 4)
    for config in configs:
        r = build(config, args.model)
        results["configs"][config] = {
            "recall": recall(r, args.data, gold),
            "latency": latency(r, args.data),
        }
        print(f"# {config}: recall + latency done", file=sys.stderr)

    for config, size in (("t0", args.size_mb), ("t0_t2", args.ner_size_mb)):
        if config not in configs:
            continue
        r = build(config, args.model)
        # The parallel engine splits only ranges of >= MIN_RANGE_BYTES (8 MiB, to
        # amortize worker start-up), so each worker gets one range or the run is
        # silently sequential. With the NER tier inference dwarfs start-up, so the
        # harness (only) lowers the floor to keep its runs to minutes.
        parallel.MIN_RANGE_BYTES = (1 << 20) if config == "t0_t2" else (8 << 20)
        mbps, sizes = {}, {}
        for w in args.workers:
            sizes[w] = max(size, parallel.MIN_RANGE_BYTES * w / 1e6 * 1.05) if w > 1 else size
            generate(args.data, sizes[w])
            mbps[w] = throughput(r, args.data, w)
            print(f"# {config} workers={w} ({sizes[w]:.0f} MB): {mbps[w]} MB/s", file=sys.stderr)
        results["configs"][config]["throughput_mb_s"] = mbps
        results["configs"][config]["throughput_corpus_mb"] = sizes
    args.data.unlink()

    print(f"model input fraction (chars the NER reads): {results['model_input_fraction']:.2%}")
    for config, res in results["configs"].items():
        rec = res["recall"]
        print(f"\n[{config}]")
        for cat in ("structured", "person"):
            c = rec[cat]
            print(
                f"  recall {cat:10s} {c['recall']:.4f}  ({c['found']}/{c['total']})  {c['by_type']}"
            )
        lat = res["latency"]
        print(f"  latency per 64 KiB window: p50 {lat['p50_ms']} ms, p99 {lat['p99_ms']} ms")
        print(f"  throughput MB/s by workers: {res['throughput_mb_s']}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\n-- wrote {args.json}")


if __name__ == "__main__":
    main()
