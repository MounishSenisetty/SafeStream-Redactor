"""Benchmark SafeStream-Redactor (and optionally Microsoft Presidio) on the
synthetic labeled dataset produced by ``generate_dataset.py``.

Reports precision / recall / F1 (span-overlap matching, type-aware) and
throughput in MB/s.

Usage::

    python benchmarks/generate_dataset.py --size-mb 10
    python benchmarks/run_benchmark.py

Presidio is only benchmarked if installed::

    pip install 'safestream-redactor[bench]'
    python -m spacy download en_core_web_lg
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from safestream_redactor import Redactor

TYPES = ["email", "phone", "credit_card", "ssn", "ipv4"]


def spans_match(pred: tuple[int, int], gold: tuple[int, int]) -> bool:
    """Predicted span counts as a hit if it overlaps >=50% of the gold span."""
    inter = min(pred[1], gold[1]) - max(pred[0], gold[0])
    return inter > 0 and inter >= 0.5 * (gold[1] - gold[0])


def score(predictions: list[dict], gold: list[dict]) -> dict[str, float]:
    # Bucket gold spans by type and sort by start so each prediction only probes
    # a small local window (near-linear overall) instead of scanning all gold.
    import bisect
    from collections import defaultdict

    buckets: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for g in gold:
        buckets[g["type"]].append((g["start"], g["end"]))
    starts: dict[str, list[int]] = {}
    matched: dict[str, set[int]] = {}
    for t, spans in buckets.items():
        spans.sort()
        buckets[t] = spans
        starts[t] = [s for s, _ in spans]
        matched[t] = set()

    tp = 0
    for pred in predictions:
        spans = buckets.get(pred["type"])
        if not spans:
            continue
        # candidate gold spans start at most at pred_end; scan back from there
        j = bisect.bisect_right(starts[pred["type"]], pred["end"]) - 1
        while j >= 0 and spans[j][1] > pred["start"]:  # while gold_end could overlap
            if j not in matched[pred["type"]] and spans_match(
                (pred["start"], pred["end"]), spans[j]
            ):
                matched[pred["type"]].add(j)
                tp += 1
                break
            j -= 1
    fp = len(predictions) - tp
    fn = len(gold) - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def bench_safestream(text: str) -> tuple[list[dict], float]:
    redactor = Redactor(types=TYPES)
    t0 = time.perf_counter()
    preds = [
        {"start": d.start, "end": d.end, "type": d.entity_type.value} for d in redactor.detect(text)
    ]
    return preds, time.perf_counter() - t0


PRESIDIO_TYPE_MAP = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "CREDIT_CARD": "credit_card",
    "US_SSN": "ssn",
    "IP_ADDRESS": "ipv4",
}


def bench_presidio(text: str) -> tuple[list[dict], float] | None:
    """Run Presidio's pattern recognizers directly.

    The compared types (email/phone/credit_card/ssn/ipv4) are pattern- and
    ``phonenumbers``-based in Presidio and do not use the spaCy NLP model, so
    running the recognizers directly is a faithful measure of Presidio for
    these types — and works fully offline (no ~600 MB model download).
    """
    try:
        from presidio_analyzer.predefined_recognizers import (
            CreditCardRecognizer,
            EmailRecognizer,
            IpRecognizer,
            PhoneRecognizer,
            UsSsnRecognizer,
        )
    except ImportError:
        return None
    recognizers = [
        EmailRecognizer(),
        PhoneRecognizer(),
        CreditCardRecognizer(),
        UsSsnRecognizer(),
        IpRecognizer(),
    ]
    t0 = time.perf_counter()
    preds = [
        {"start": r.start, "end": r.end, "type": PRESIDIO_TYPE_MAP[r.entity_type]}
        for rec in recognizers
        for r in rec.analyze(text, entities=rec.supported_entities, nlp_artifacts=None)
        if r.entity_type in PRESIDIO_TYPE_MAP
    ]
    return preds, time.perf_counter() - t0


def report(name: str, metrics: dict[str, float], seconds: float, size_mb: float) -> None:
    print(
        f"{name:<22} P={metrics['precision']:.3f}  R={metrics['recall']:.3f}  "
        f"F1={metrics['f1']:.3f}  {size_mb / seconds:8.2f} MB/s  "
        f"(tp={metrics['tp']} fp={metrics['fp']} fn={metrics['fn']})"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(__file__).parent / "data")
    args = ap.parse_args()

    corpus = args.data / "dataset.txt"
    if not corpus.exists():
        raise SystemExit(f"{corpus} not found — run benchmarks/generate_dataset.py first")
    text = corpus.read_text(encoding="utf-8")
    gold = json.loads((args.data / "dataset.json").read_text(encoding="utf-8"))
    size_mb = len(text.encode()) / 1e6
    print(f"corpus: {size_mb:.1f} MB, {len(gold)} gold entities\n")

    preds, seconds = bench_safestream(text)
    report("safestream-redactor", score(preds, gold), seconds, size_mb)

    presidio = bench_presidio(text)
    if presidio is None:
        print("presidio              (not installed — pip install 'safestream-redactor[bench]')")
    else:
        preds, seconds = presidio
        report("presidio", score(preds, gold), seconds, size_mb)


if __name__ == "__main__":
    main()
