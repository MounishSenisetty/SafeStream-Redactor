"""Forensic instrumentation of the SafeStream pipeline on RedactionBench.

This traces every *mandatory* gold character through the real pipeline stages and
attributes each loss to exactly one cause, so the bottleneck is identified from
evidence rather than assertion. It reconstructs the same stages
``Redactor.detect`` runs — raw candidates (per detector, pre-filter,
pre-reconciliation) → contextual adjust → confidence filter → overlap
reconciliation → streaming output — and, for each gold span, asks at which stage
its characters stopped being covered.

Failure categories (mutually exclusive, char-weighted per span):
  never_detected       no raw candidate covered >=50% of the span
  confidence_rejected  a raw candidate covered it, but none survived min_confidence
  reconciliation_lost  survived the filter, but overlap resolution dropped it
  streaming_lost       final whole-doc detection covered it, but streaming did not
  boundary_partial     covered >=50% but not the exact span (truncation/boundary)
  covered_exact        covered with exact boundaries

Nothing here is RedactionBench-specific: it inspects the generic pipeline.
Run: python -m benchmarks.redactionbench.diagnose --data-dir benchmarks/data/redactionbench
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from safestream_redactor import Redactor
from safestream_redactor.entities import Detection, resolve_overlaps

from . import adapter, loader


def _mask(spans: list[tuple[int, int]], n: int) -> bytearray:
    m = bytearray(n)
    for s, e in spans:
        for i in range(max(0, s), min(n, e)):
            m[i] = 1
    return m


def _covered(mask: bytearray, s: int, e: int) -> int:
    return sum(mask[i] for i in range(max(0, s), min(len(mask), e)))


# ---- reconstruct the pipeline stages of Redactor.detect, keeping each stage ----


def _pipeline_stages(red: Redactor, text: str) -> dict[str, list[Detection]]:
    raw: list[Detection] = []
    for det in red._detectors:
        raw.extend(det.detect(text))
    # copy raw offsets before adjust mutates confidences in place
    red._scorer.adjust(text, raw)
    if red.calibrator is not None:
        for d in raw:
            d.confidence = red.calibrator.predict_one(d)
    confident = [d for d in raw if d.confidence >= red.min_confidence]
    final = resolve_overlaps(confident)
    return {"raw": raw, "confident": confident, "final": final}


def decompose(rows: list[dict[str, Any]], red: Redactor) -> dict[str, Any]:
    cat_chars: Counter[str] = Counter()
    cat_spans: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    total_mand_chars = 0
    for r in rows:
        t = r["raw_text"]
        n = len(t)
        stages = _pipeline_stages(red, t)
        raw_m = _mask([(d.start, d.end) for d in stages["raw"]], n)
        conf_m = _mask([(d.start, d.end) for d in stages["confident"]], n)
        final_m = _mask([(d.start, d.end) for d in stages["final"]], n)
        stream_m = _mask(
            [(p.start, p.end) for p in adapter.predict_streaming(red, t, chunk_size=4096)], n
        )
        for s in r["spans"]:
            if s["label"] != "mandatory":
                continue
            a, b = s["start"], s["end"]
            L = b - a
            total_mand_chars += L
            rawc, confc, finc, strc = (
                _covered(raw_m, a, b),
                _covered(conf_m, a, b),
                _covered(final_m, a, b),
                _covered(stream_m, a, b),
            )
            if rawc < 0.5 * L:
                cat = "never_detected"
            elif confc < 0.5 * L:
                cat = "confidence_rejected"
            elif finc < 0.5 * L:
                cat = "reconciliation_lost"
            elif strc < 0.5 * L:
                cat = "streaming_lost"
            elif strc == L and _exact_boundary(stages["final"], a, b):
                cat = "covered_exact"
            else:
                cat = "boundary_partial"
            cat_chars[cat] += L
            cat_spans[cat] += 1
            if cat not in ("covered_exact",) and len(examples[cat]) < 6:
                examples[cat].append(t[a:b][:40])
    return {
        "total_mandatory_chars": total_mand_chars,
        "by_category_chars": dict(cat_chars.most_common()),
        "by_category_spans": dict(cat_spans.most_common()),
        "examples": {k: v for k, v in examples.items()},
    }


def _exact_boundary(final: list[Detection], a: int, b: int) -> bool:
    return any(d.start == a and d.end == b for d in final)


# ---- per-detector ablation: mandatory char recall for detector combinations ----


def ablation(rows: list[dict[str, Any]], use_ner: bool = False) -> dict[str, float]:
    from safestream_redactor.detectors.contextual import ContextualScorer
    from safestream_redactor.detectors.deterministic import DeterministicDetector
    from safestream_redactor.detectors.entropy import EntropyDetector
    from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector

    def recall(detectors_factory: Any, reconcile: bool) -> float:
        tp = fn = 0
        scorer = ContextualScorer()
        dets = detectors_factory()
        for r in rows:
            t = r["raw_text"]
            n = len(t)
            raw: list[Detection] = []
            for d in dets:
                raw.extend(d.detect(t))
            if reconcile:
                scorer.adjust(t, raw)
                raw = resolve_overlaps([d for d in raw if d.confidence >= 0.5])
            m = _mask([(d.start, d.end) for d in raw], n)
            for s in r["spans"]:
                if s["label"] != "mandatory":
                    continue
                c = _covered(m, s["start"], s["end"])
                L = s["end"] - s["start"]
                if c >= 0.5 * L:
                    tp += 1
                else:
                    fn += 1
        return tp / (tp + fn) if (tp + fn) else 0.0

    det = lambda: [DeterministicDetector(None)]  # noqa: E731
    det_ent = lambda: [DeterministicDetector(None), EntropyDetector()]  # noqa: E731
    det_lab = lambda: [DeterministicDetector(None), LabeledIdentifierDetector()]  # noqa: E731
    full = lambda: [  # noqa: E731
        DeterministicDetector(None),
        LabeledIdentifierDetector(),
        EntropyDetector(),
    ]
    out = {
        "1_deterministic_only": recall(det, reconcile=False),
        "2_det+entropy": recall(det_ent, reconcile=False),
        "4_det+labeled(contextual)": recall(det_lab, reconcile=False),
        "5_full+reconciliation": recall(full, reconcile=True),
    }
    if use_ner:
        from safestream_redactor.detectors.ner import NERDetector

        ner_full = lambda: [  # noqa: E731
            DeterministicDetector(None),
            LabeledIdentifierDetector(),
            EntropyDetector(),
            NERDetector(),
        ]
        out["3_full+NER+reconciliation"] = recall(ner_full, reconcile=True)
    return out


# ---- boundary-failure matrix: synthetic entity at every offset mod chunk ----


def boundary_matrix(chunk_size: int = 64, overlap: int | None = None) -> dict[str, Any]:
    """Place a known entity at every offset relative to a chunk boundary and
    confirm streaming detection equals whole-document detection at each position.
    """
    red = Redactor(overlap=overlap) if overlap else Redactor()
    entity = "bob@corp.io"  # a deterministic, unambiguous entity
    failures = []
    tested = 0
    for pad in range(0, chunk_size * 2 + 5):
        text = ("x" * pad) + f" contact {entity} end " + ("y" * 50)
        tested += 1
        whole = {(p.start, p.end) for p in adapter.predict_whole(red, text)}
        stream = {(p.start, p.end) for p in adapter.predict_streaming(red, text, chunk_size)}
        if whole != stream:
            failures.append({"pad": pad, "whole": sorted(whole), "stream": sorted(stream)})
    return {"positions_tested": tested, "chunk_size": chunk_size, "boundary_failures": failures}


# ---- detection vs redaction split ----


def detection_vs_redaction(rows: list[dict[str, Any]], red: Redactor) -> dict[str, int]:
    """For each mandatory span: recognized (raw)? survived reconciliation (final)?
    actually redacted by streaming output? Distinguishes detector recall from
    span/redaction-architecture loss.
    """
    recognized = preserved = redacted = total = 0
    for r in rows:
        t = r["raw_text"]
        n = len(t)
        stages = _pipeline_stages(red, t)
        raw_m = _mask([(d.start, d.end) for d in stages["raw"]], n)
        final_m = _mask([(d.start, d.end) for d in stages["final"]], n)
        stream_m = _mask(
            [(p.start, p.end) for p in adapter.predict_streaming(red, t, chunk_size=4096)], n
        )
        for s in r["spans"]:
            if s["label"] != "mandatory":
                continue
            a, b = s["start"], s["end"]
            L = b - a
            total += 1
            recognized += _covered(raw_m, a, b) >= 0.5 * L
            preserved += _covered(final_m, a, b) >= 0.5 * L
            redacted += _covered(stream_m, a, b) >= 0.5 * L
    return {
        "mandatory_spans": total,
        "recognized_by_a_detector": recognized,
        "preserved_after_reconciliation": preserved,
        "redacted_in_streaming_output": redacted,
    }


def _heuristic_type(v: str) -> str:
    s = v.strip()
    if re.fullmatch(r"[\w.+-]+@[\w.-]+\.\w+", s):
        return "email"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s):
        return "ipv4"
    if re.fullmatch(r"[A-Z][A-Za-zÀ-ÿ'.-]*(\s+[A-Z][A-Za-zÀ-ÿ'.-]*)*", s) and not s.isdigit():
        return "name"
    if re.fullmatch(r"[\d\s/.:-]+", s):
        return "number/date"
    if re.fullmatch(r"[A-Za-z0-9._/+!@#-]{6,}", s):
        return "alnum/token"
    return "other"


def per_type(rows: list[dict[str, Any]], red: Redactor) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, int]] = defaultdict(
        lambda: {"instances": 0, "detected": 0, "exact": 0}
    )
    for r in rows:
        t = r["raw_text"]
        n = len(t)
        final = red.detect(t)
        m = _mask([(d.start, d.end) for d in final], n)
        exact = {(d.start, d.end) for d in final}
        for s in r["spans"]:
            if s["label"] != "mandatory":
                continue
            a, b = s["start"], s["end"]
            ty = _heuristic_type(t[a:b])
            rec = out[ty]
            rec["instances"] += 1
            if _covered(m, a, b) >= 0.5 * (b - a):
                rec["detected"] += 1
            if (a, b) in exact:
                rec["exact"] += 1
    return {
        ty: {
            **rec,
            "recall": round(rec["detected"] / rec["instances"], 3) if rec["instances"] else 0.0,
            "boundary_exact_rate": round(rec["exact"] / max(1, rec["detected"]), 3),
        }
        for ty, rec in sorted(out.items(), key=lambda kv: -kv[1]["instances"])
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default="benchmarks/data/redactionbench")
    ap.add_argument("--ner", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)

    res = loader.load_from_directory(Path(args.data_dir), loader.FieldSpec())
    rows = [
        {
            "raw_text": rec.text,
            "spans": [{"start": s.start, "end": s.end, "label": s.label} for s in rec.spans],
        }
        for rec in res.records
    ]
    if args.limit:
        rows = rows[: args.limit]
    red = Redactor(use_ner=args.ner)

    import json

    print("=== FAILURE DECOMPOSITION (mandatory chars) ===")
    dec = decompose(rows, red)
    tot = dec["total_mandatory_chars"]
    for cat, ch in dec["by_category_chars"].items():
        spans = dec["by_category_spans"].get(cat)
        print(f"  {cat:<22} {ch:>7} chars ({100 * ch / tot:5.1f}%)  spans={spans}")
    print("\n  examples:")
    for cat, ex in dec["examples"].items():
        print(f"    {cat}: {ex}")

    print("\n=== DETECTION vs REDACTION ===")
    print(json.dumps(detection_vs_redaction(rows, red), indent=2))

    print("\n=== DETECTOR ABLATION (mandatory span recall, >=50% char overlap) ===")
    for k, v in sorted(ablation(rows, use_ner=args.ner).items()):
        print(f"  {k:<32} {v:.3f}")

    print("\n=== BOUNDARY MATRIX (streaming vs whole at every offset) ===")
    for cs in (16, 32, 64):
        bm = boundary_matrix(chunk_size=cs)
        nfail = len(bm["boundary_failures"])
        print(f"  chunk={cs}: positions={bm['positions_tested']} failures={nfail}")

    print("\n=== PER (heuristic) TYPE ===")
    print(json.dumps(per_type(rows, red), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
