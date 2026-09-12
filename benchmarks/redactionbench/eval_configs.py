"""Config comparison harness: semantic-detector configurations vs baseline.

Measures, for a detector configuration, on the full RedactionBench corpus (and an
optional benign public-prose set): character precision/recall/F1, mandatory
recall, per-class (A objective / B semantic / C ambiguous / D glue) recall,
false-positive characters, throughput (chars/s), per-document latency, process
peak RSS, and startup cost. Also runs a min-confidence threshold sweep.

Configs (build the shipped pipeline plus optional semantic tiers):
  core        deterministic + entropy + labeled-id + contextual
  gazetteer   core + model-free gazetteer/context name detector
  ner         core + spaCy NER
  ner+gaz     core + spaCy NER + gazetteer (ensemble)
  onnx        core + ONNX NER (needs --onnx-model/--onnx-vocab[/--onnx-labels])

Run one config per process so peak RSS is attributable:
  python -m benchmarks.redactionbench.eval_configs --config ner --benign
  python -m benchmarks.redactionbench.eval_configs --config gazetteer --sweep 0.5,0.6,0.72,0.85
"""

from __future__ import annotations

import argparse
import json
import re
import resource
import time
from pathlib import Path
from typing import Any

from safestream_redactor import Redactor

from . import adapter, loader, metrics

# ---- A/B/C/D content classifier (same scheme as the validity audit) ----------

_RE_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_RE_IPV4 = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
_RE_SSN = re.compile(r"\d{3}-\d{2}-\d{4}")
_RE_NAME = re.compile(r"[A-Z][A-Za-zÀ-ÿ'.-]*(\s+[A-Z][A-Za-zÀ-ÿ'.-]*)*")


def classify(v: str) -> str:
    s = v.strip()
    if not s or re.fullmatch(r"[^\w\s]+", v):
        return "D_glue"
    if _RE_EMAIL.fullmatch(s) or _RE_IPV4.fullmatch(s) or _RE_SSN.search(s):
        return "A_objective"
    if (
        re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", s)
        and any(c.isdigit() for c in s)
        and any(c.isalpha() for c in s)
    ):
        return "A_objective"
    if _RE_NAME.fullmatch(s) and not s.isdigit():
        return "B_semantic"
    if re.fullmatch(r"[\d/.:-]+", s):
        return "C_ambiguous"
    return "C_ambiguous"


def build_redactor(config: str, min_conf: float, args: argparse.Namespace) -> Redactor:
    kw: dict[str, Any] = {"min_confidence": min_conf}
    if config in ("gazetteer", "ner+gaz"):
        kw["use_gazetteer"] = True
    if config in ("ner", "ner+gaz"):
        kw["use_ner"] = True
    if config == "onnx":
        if not (args.onnx_model and args.onnx_vocab):
            raise SystemExit("--config onnx needs --onnx-model and --onnx-vocab")
        kw.update(
            use_onnx=True,
            onnx_model=args.onnx_model,
            onnx_vocab=args.onnx_vocab,
            onnx_labels=args.onnx_labels,
        )
    return Redactor(**kw)


def _mask(spans: list[tuple[int, int]], n: int) -> bytearray:
    m = bytearray(n)
    for s, e in spans:
        for i in range(max(0, s), min(n, e)):
            m[i] = 1
    return m


def evaluate_rb(red: Redactor, rows: list[dict[str, Any]], chunk: int) -> dict[str, Any]:
    chars = {k: metrics.CharCounts(0, 0, 0, 0) for k in ("all", "mandatory", "contextual")}
    per_class = {c: [0, 0] for c in ("A_objective", "B_semantic", "C_ambiguous", "D_glue")}
    latencies: list[float] = []
    total_chars = 0
    t0 = time.perf_counter()
    for r in rows:
        t = r["raw_text"]
        n = len(t)
        total_chars += n
        d0 = time.perf_counter()
        preds = adapter.predict_streaming(red, t, chunk)
        latencies.append(time.perf_counter() - d0)
        pm = _mask([(p.start, p.end) for p in preds], n)
        gold_all = [(s["start"], s["end"]) for s in r["spans"]]
        gold_mand = [(s["start"], s["end"]) for s in r["spans"] if s["label"] == "mandatory"]
        gold_ctx = [(s["start"], s["end"]) for s in r["spans"] if s["label"] == "contextual"]
        chars["all"] = chars["all"] + metrics.score_chars(
            gold_all, [(p.start, p.end) for p in preds], n
        )
        chars["mandatory"] = chars["mandatory"] + metrics.score_chars(
            gold_mand, [(p.start, p.end) for p in preds], n
        )
        chars["contextual"] = chars["contextual"] + metrics.score_chars(
            gold_ctx, [(p.start, p.end) for p in preds], n
        )
        for s in r["spans"]:
            if s["label"] != "mandatory":
                continue
            cls = classify(t[s["start"] : s["end"]])
            cov = sum(pm[i] for i in range(s["start"], s["end"]) if i < n)
            per_class[cls][1] += 1
            if cov >= 0.5 * (s["end"] - s["start"]):
                per_class[cls][0] += 1
    elapsed = time.perf_counter() - t0
    latencies.sort()
    a = chars["all"]
    return {
        "char_precision": round(a.precision, 4),
        "char_recall": round(a.recall, 4),
        "char_f1": round(a.f1, 4),
        "mandatory_recall": round(chars["mandatory"].recall, 4),
        "contextual_recall": round(chars["contextual"].recall, 4),
        "false_positive_chars": a.fp,
        "false_negative_chars": a.fn,
        "per_class_recall": {
            c: {
                "detected": v[0],
                "instances": v[1],
                "recall": round(v[0] / v[1], 3) if v[1] else 0.0,
            }
            for c, v in per_class.items()
        },
        "throughput_chars_per_s": round(total_chars / elapsed) if elapsed else 0,
        "latency_ms_mean": round(1000 * sum(latencies) / len(latencies), 2),
        "latency_ms_p95": round(1000 * latencies[int(0.95 * len(latencies))], 2),
        "docs": len(rows),
        "total_chars": total_chars,
    }


def evaluate_benign(red: Redactor, rows: list[dict[str, Any]], chunk: int) -> dict[str, Any]:
    total = redacted = 0
    examples: list[str] = []
    for r in rows:
        t = r["raw_text"]
        n = len(t)
        total += n
        preds = adapter.predict_streaming(red, t, chunk)
        pm = _mask([(p.start, p.end) for p in preds], n)
        redacted += sum(pm)
        for p in preds:
            if len(examples) < 25:
                examples.append(f"{p.label}:{t[p.start : p.end]!r}")
    return {
        "benign_docs": len(rows),
        "benign_chars": total,
        "benign_redacted_chars": redacted,
        "benign_fp_rate": round(redacted / total, 4) if total else 0.0,
        "benign_redactions": examples,
    }


def _load_rows(data_dir: str) -> list[dict[str, Any]]:
    res = loader.load_from_directory(Path(data_dir), loader.FieldSpec())
    return [
        {
            "raw_text": rec.text,
            "spans": [{"start": s.start, "end": s.end, "label": s.label} for s in rec.spans],
        }
        for rec in res.records
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--config", default="core", choices=["core", "gazetteer", "ner", "ner+gaz", "onnx"]
    )
    ap.add_argument("--data-dir", default="benchmarks/data/redactionbench")
    ap.add_argument("--benign-dir", default="benchmarks/data/benign")
    ap.add_argument("--chunk-size", type=int, default=4096)
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--benign", action="store_true", help="also evaluate the benign FP set")
    ap.add_argument("--sweep", default="", help="comma-separated min-confidence values to sweep")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--onnx-model")
    ap.add_argument("--onnx-vocab")
    ap.add_argument("--onnx-labels")
    args = ap.parse_args(argv)

    rows = _load_rows(args.data_dir)
    if args.limit:
        rows = rows[: args.limit]

    thresholds = (
        [float(x) for x in args.sweep.split(",") if x.strip()]
        if args.sweep
        else [args.min_confidence]
    )

    results = []
    for thr in thresholds:
        t_start = time.perf_counter()
        red = build_redactor(args.config, thr, args)
        startup_s = round(time.perf_counter() - t_start, 3)
        row: dict[str, Any] = {"config": args.config, "min_confidence": thr, "startup_s": startup_s}
        row.update(evaluate_rb(red, rows, args.chunk_size))
        if args.benign:
            row.update(evaluate_benign(red, _load_rows(args.benign_dir), args.chunk_size))
        row["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
        results.append(row)

    if len(thresholds) > 1:
        print(f"\n=== THRESHOLD SWEEP: {args.config} ===")
        print(
            f"{'thr':>5}{'PChar':>8}{'RChar':>8}{'F1':>8}{'Mand':>8}{'benignFP':>10}{'thru/s':>10}{'RSSmb':>8}"
        )
        for r in results:
            bfp = r.get("benign_fp_rate", "-")
            print(
                f"{r['min_confidence']:>5}{r['char_precision']:>8}{r['char_recall']:>8}"
                f"{r['char_f1']:>8}{r['mandatory_recall']:>8}{bfp!s:>10}"
                f"{r['throughput_chars_per_s']:>10}{r['peak_rss_mb']:>8}"
            )
    print("\n" + json.dumps(results if len(results) > 1 else results[0], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
