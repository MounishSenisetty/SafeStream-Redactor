"""Train a confidence calibrator and run the per-tier ablation (WI-9).

Two things a reviewer asks for and this script produces:

1. **A calibrator.** The built-in confidences are hand-set constants. This
   trains a logistic calibrator (``safestream_redactor.calibration``) on a
   labeled corpus so the confidences become probabilities, and reports how much
   better calibrated they are (Brier score and expected calibration error,
   before vs after). Save the model and point a policy's ``[calibration]``
   section at it.

2. **A per-tier ablation.** Turning each optional tier off in turn and measuring
   the micro-F1 drop shows the marginal value of each — the table that answers
   "does the entropy tier actually earn its false positives?".

The corpus is loaded with the same loaders as ``evaluate.py`` (``--jsonl``,
``--conll``, ``--presidio-json``, or ``--text``/``--gold``) and mapped with
``--label-map``.

Example::

    python benchmarks/calibrate.py --jsonl labeled.jsonl \\
        --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn \\
        --out calibrator.json
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import evaluate

from safestream_redactor import Calibrator, Redactor
from safestream_redactor.calibration import features

Labeled = tuple[list[float], int]


def build_training_set(
    records: list[tuple[str, list[evaluate.Span]]], eval_types: set[str], *, use_ner: bool
) -> tuple[list[list[float]], list[int], list[float]]:
    """Feature rows, 0/1 labels, and each detection's raw confidence.

    Every candidate detection (thresholded at 0 so nothing is dropped before it
    can be judged) is labeled a true positive when it overlaps a gold span of
    the same type. The raw confidences are returned alongside so the report can
    compare calibrated probabilities against the hand-set constants.
    """
    redactor = Redactor(min_confidence=0.0, use_ner=use_ner)
    rows: list[list[float]] = []
    labels: list[int] = []
    raw_conf: list[float] = []
    for text, gold in records:
        gold_t = [(s, e, t) for s, e, t in gold if t in eval_types]
        for d in redactor.detect(text):
            if d.entity_type.value not in eval_types:
                continue
            hit = any(
                t == d.entity_type.value and evaluate.spans_match((d.start, d.end), (s, e))
                for s, e, t in gold_t
            )
            rows.append(features(d))
            labels.append(1 if hit else 0)
            raw_conf.append(d.confidence)
    return rows, labels, raw_conf


def brier(probs: list[float], labels: list[int]) -> float:
    return sum((p - y) ** 2 for p, y in zip(probs, labels, strict=True)) / max(1, len(labels))


def ece(probs: list[float], labels: list[int], *, bins: int = 10) -> float:
    """Expected calibration error: |accuracy - confidence| averaged over bins."""
    n = len(labels)
    if n == 0:
        return 0.0
    total = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if (lo <= p < hi or (b == bins - 1 and p == 1.0))]
        if not idx:
            continue
        conf = sum(probs[i] for i in idx) / len(idx)
        acc = sum(labels[i] for i in idx) / len(idx)
        total += (len(idx) / n) * abs(acc - conf)
    return total


def ablation(
    records: list[tuple[str, list[evaluate.Span]]],
    eval_types: set[str],
    calibrator: Calibrator,
    *,
    use_ner: bool,
) -> list[tuple[str, float]]:
    """Micro-F1 of the full system and of each ablated variant."""
    variants: list[tuple[str, evaluate.Adapter]] = [
        ("full (hand-set)", evaluate.safestream_adapter(use_ner=use_ner)),
        ("full + calibrated", evaluate.safestream_adapter(use_ner=use_ner, calibrator=calibrator)),
        ("no entropy tier", _no_entropy_adapter(use_ner=use_ner)),
    ]
    if use_ner:
        variants.append(("no NER tier", evaluate.safestream_adapter(use_ner=False)))
    out = []
    for name, adapter in variants:
        per_record = evaluate.score_all(records, adapter, eval_types)
        out.append((name, evaluate._micro_f1(per_record, eval_types)))
    return out


def _no_entropy_adapter(*, use_ner: bool) -> evaluate.Adapter:
    redactor = Redactor(use_ner=use_ner, use_entropy=False)

    def run(text: str) -> list[evaluate.Span]:
        return [(d.start, d.end, d.entity_type.value) for d in redactor.detect(text)]

    return run


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--jsonl", type=Path)
    ap.add_argument("--text", type=Path)
    ap.add_argument("--gold", type=Path)
    ap.add_argument("--conll", type=Path)
    ap.add_argument("--presidio-json", type=Path)
    ap.add_argument("--label-map", default="")
    ap.add_argument("--ner", action="store_true", help="include the spaCy NER tier")
    ap.add_argument("--out", type=Path, help="write the trained calibrator here (JSON)")
    ap.add_argument("--l2", type=float, default=1.0)
    ap.add_argument("--epochs", type=int, default=2000)
    args = ap.parse_args()

    records = evaluate.load_records(args)
    label_map = evaluate.parse_label_map(args.label_map)
    if label_map:
        records = [
            (text, [(s, e, label_map[t]) for s, e, t in spans if t in label_map])
            for text, spans in records
        ]
    eval_types = {t for _, spans in records for _, _, t in spans}
    if not eval_types:
        raise SystemExit("no gold spans after label mapping — check --label-map")

    rows, labels, raw_conf = build_training_set(records, eval_types, use_ner=args.ner)
    if not rows:
        raise SystemExit("no candidate detections to train on")
    pos = sum(labels)
    print(f"training on {len(rows)} candidate detections ({pos} TP, {len(rows) - pos} FP)\n")

    cal = Calibrator.fit(rows, labels, l2=args.l2, epochs=args.epochs)
    cal_probs = [cal.predict(r) for r in rows]

    print(f"{'metric':<20}{'hand-set':>12}{'calibrated':>12}")
    print(f"{'Brier score':<20}{brier(raw_conf, labels):>12.4f}{brier(cal_probs, labels):>12.4f}")
    print(f"{'ECE':<20}{ece(raw_conf, labels):>12.4f}{ece(cal_probs, labels):>12.4f}")
    print("  (lower is better for both; calibration should reduce them)\n")

    print("per-tier ablation (micro-F1):")
    for name, f1 in ablation(records, eval_types, cal, use_ner=args.ner):
        print(f"  {name:<20}{f1:>8.3f}")

    if args.out:
        cal.save(args.out)
        print(f"\nsaved calibrator to {args.out}")


if __name__ == "__main__":
    main()
