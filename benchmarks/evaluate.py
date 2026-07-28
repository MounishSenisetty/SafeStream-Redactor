"""Accuracy evaluation against an INDEPENDENT, externally-labeled corpus.

Unlike ``run_benchmark.py`` (which scores against self-generated synthetic
text and therefore measures format coverage, not accuracy), this harness is
meant to be pointed at a corpus you did not generate — the Presidio research
dataset, CoNLL-2003, the n2c2/i2b2 de-identification set, or your own labeled
logs — so the resulting precision/recall are defensible real-world numbers.

Nothing is bundled (those corpora carry their own licenses); you supply the
data. Two input shapes are accepted:

1. ``--text corpus.txt --gold gold.json`` where ``gold.json`` is a list of
   ``{"start": int, "end": int, "type": str}`` spans into the text.
2. ``--jsonl records.jsonl`` where each line is
   ``{"text": str, "spans": [{"start", "end", "type"}, ...]}``.

External datasets label with their own type names, so map them onto SafeStream
entity types with ``--label-map`` (matching is type-aware). Only the mapped
types are scored, so a corpus that annotates only PERSON does not penalize
SafeStream for also detecting emails it never labeled.

Example (Presidio research dataset, converted to the jsonl shape)::

    python benchmarks/evaluate.py --jsonl presidio_eval.jsonl \\
        --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn,\\
US_PHONE_NUMBER=phone,CREDIT_CARD=credit_card,IP_ADDRESS=ipv4 --ner
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from safestream_redactor import Redactor

Span = tuple[int, int, str]


def spans_match(pred: tuple[int, int], gold: tuple[int, int]) -> bool:
    """A prediction hits a gold span when it overlaps at least 50% of it."""
    inter = min(pred[1], gold[1]) - max(pred[0], gold[0])
    return inter > 0 and inter >= 0.5 * (gold[1] - gold[0])


def score_record(
    gold: list[Span], preds: list[Span], eval_types: set[str]
) -> dict[str, tuple[int, int, int]]:
    """Per-type (tp, fp, fn) for one record, restricted to ``eval_types``."""
    gold_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in gold:
        if t in eval_types:
            gold_by_type[t].append((s, e))
    pred_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in preds:
        if t in eval_types:
            pred_by_type[t].append((s, e))

    out: dict[str, tuple[int, int, int]] = {}
    for t in eval_types:
        golds = gold_by_type.get(t, [])
        matched = set()
        tp = 0
        for ps, pe in pred_by_type.get(t, []):
            for i, g in enumerate(golds):
                if i not in matched and spans_match((ps, pe), g):
                    matched.add(i)
                    tp += 1
                    break
        fp = len(pred_by_type.get(t, [])) - tp
        fn = len(golds) - tp
        out[t] = (tp, fp, fn)
    return out


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def parse_label_map(spec: str) -> dict[str, str]:
    mapping = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        src, _, dst = pair.partition("=")
        if not dst:
            raise SystemExit(f"--label-map expects SRC=dst pairs, got {pair!r}")
        mapping[src.strip()] = dst.strip()
    return mapping


def load_records(args: argparse.Namespace) -> list[tuple[str, list[Span]]]:
    records: list[tuple[str, list[Span]]] = []
    if args.jsonl:
        for line in Path(args.jsonl).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            spans = [(s["start"], s["end"], s["type"]) for s in obj.get("spans", [])]
            records.append((obj["text"], spans))
    else:
        if not (args.text and args.gold):
            raise SystemExit("provide either --jsonl, or both --text and --gold")
        text = Path(args.text).read_text(encoding="utf-8")
        gold = json.loads(Path(args.gold).read_text(encoding="utf-8"))
        records.append((text, [(g["start"], g["end"], g["type"]) for g in gold]))
    return records


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--jsonl", type=Path, help="records file (one JSON object per line)")
    ap.add_argument("--text", type=Path, help="corpus text file (with --gold)")
    ap.add_argument("--gold", type=Path, help="gold spans JSON (with --text)")
    ap.add_argument(
        "--label-map",
        default="",
        help="comma-separated SRC=safestream_type pairs mapping the corpus's labels",
    )
    ap.add_argument("--ner", action="store_true", help="enable the spaCy NER tier")
    args = ap.parse_args()

    label_map = parse_label_map(args.label_map)
    records = load_records(args)
    if label_map:
        records = [
            (text, [(s, e, label_map[t]) for s, e, t in spans if t in label_map])
            for text, spans in records
        ]
    eval_types = {t for _, spans in records for _, _, t in spans}
    if not eval_types:
        raise SystemExit("no gold spans after label mapping — check --label-map")

    redactor = Redactor(use_ner=args.ner)
    totals: dict[str, list[int]] = {t: [0, 0, 0] for t in eval_types}
    for text, gold in records:
        preds = [(d.start, d.end, d.entity_type.value) for d in redactor.detect(text)]
        for t, (tp, fp, fn) in score_record(gold, preds, eval_types).items():
            totals[t][0] += tp
            totals[t][1] += fp
            totals[t][2] += fn

    print(f"corpus: {len(records)} record(s), evaluated types: {', '.join(sorted(eval_types))}\n")
    print(f"{'type':<16}{'P':>8}{'R':>8}{'F1':>8}{'tp':>8}{'fp':>8}{'fn':>8}")
    micro = [0, 0, 0]
    for t in sorted(totals):
        tp, fp, fn = totals[t]
        micro[0] += tp
        micro[1] += fp
        micro[2] += fn
        p, r, f = prf(tp, fp, fn)
        print(f"{t:<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}{tp:>8}{fp:>8}{fn:>8}")
    p, r, f = prf(*micro)
    print(f"{'MICRO-AVG':<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}{micro[0]:>8}{micro[1]:>8}{micro[2]:>8}")


if __name__ == "__main__":
    main()
