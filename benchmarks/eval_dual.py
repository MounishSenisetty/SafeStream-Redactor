"""Independent real-world accuracy evaluation.

Scores the deterministic detection core against the Microsoft ``presidio-research``
synthetic dataset — an externally-authored corpus whose PII appears in the messy,
non-canonical formats real data has, so it measures *real-world* recall rather
than format coverage. This is kept strictly separate from the project's own
synthetic regression fixture (``benchmarks/run_benchmark.py``): that one measures
false-positive resistance on adversarial distractors, this one measures recall on
independent data. Run both after any detector change.

Never edit the corpora to make numbers look better. The corpus is fetched on
demand (not vendored) from the upstream repository.

Usage::

    python benchmarks/eval_dual.py
"""

from __future__ import annotations

import collections
import json
import urllib.request
from pathlib import Path

from safestream_redactor import Redactor

_CORPUS_URL = (
    "https://raw.githubusercontent.com/microsoft/presidio-research/master/"
    "data/synth_dataset_v2.json"
)
_CORPUS_PATH = Path(__file__).parent / "external" / "presidio_synth_v2.json"

# presidio entity label -> the SafeStream types that count as a correct hit.
# Only the entity classes the deterministic core targets are scored; free-text
# PERSON/ORG/GPE need the NER tier and are out of scope here.
MAP = {
    "EMAIL_ADDRESS": {"email"},
    "PHONE_NUMBER": {"phone"},
    "CREDIT_CARD": {"credit_card"},
    "US_SSN": {"ssn"},
    "IP_ADDRESS": {"ipv4", "ipv6"},
}


def load_corpus() -> list[dict]:
    """Return the corpus, fetching and caching it under benchmarks/external/."""
    if not _CORPUS_PATH.exists():
        _CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(_CORPUS_URL, headers={"User-Agent": "safestream-eval"})
        with urllib.request.urlopen(req, timeout=60) as r:
            _CORPUS_PATH.write_bytes(r.read())
    return json.loads(_CORPUS_PATH.read_text())


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return hi > lo and (hi - lo) >= 0.5 * (b[1] - b[0])


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def evaluate(redactor: Redactor, data: list[dict]) -> dict[str, tuple]:
    """Return {label|'MICRO': (gold, tp, fp, fn, precision, recall, f1)}."""
    scored_types = {t for s in MAP.values() for t in s}
    tp: collections.Counter = collections.Counter()
    fn: collections.Counter = collections.Counter()
    fp: collections.Counter = collections.Counter()
    gold: collections.Counter = collections.Counter()
    for rec in data:
        text = rec["full_text"]
        golds = [
            (s["start_position"], s["end_position"], s["entity_type"])
            for s in rec["spans"]
            if s["entity_type"] in MAP
        ]
        for *_, t in golds:
            gold[t] += 1
        preds = [(d.start, d.end, d.entity_type.value) for d in redactor.detect(text)]
        used: set[int] = set()
        for gs, ge, gt in golds:
            hit = next(
                (
                    i
                    for i, (ps, pe, pt) in enumerate(preds)
                    if i not in used and pt in MAP[gt] and _overlap((ps, pe), (gs, ge))
                ),
                None,
            )
            if hit is None:
                fn[gt] += 1
            else:
                tp[gt] += 1
                used.add(hit)
        for i, (ps, pe, pt) in enumerate(preds):
            if (
                pt in scored_types
                and i not in used
                and not any(_overlap((ps, pe), (gs, ge)) and pt in MAP[gt] for gs, ge, gt in golds)
            ):
                fp[pt] += 1
    rows: dict[str, tuple] = {}
    tt = ff = nn = 0
    for gt in MAP:
        fpc = sum(fp[pt] for pt in MAP[gt])
        rows[gt] = (gold[gt], tp[gt], fpc, fn[gt], *_prf(tp[gt], fpc, fn[gt]))
        tt += tp[gt]
        ff += fpc
        nn += fn[gt]
    rows["MICRO"] = (sum(gold.values()), tt, ff, nn, *_prf(tt, ff, nn))
    return rows


def main() -> None:
    data = load_corpus()
    rows = evaluate(Redactor(load_plugins=False), data)
    print(f"independent corpus: presidio-research synth_dataset_v2 ({len(data)} records)")
    cols = ("type", "gold", "TP", "FP", "FN", "P", "R", "F1")
    print(f"{cols[0]:13s} " + " ".join(f"{c:>6s}" for c in cols[1:]))
    for k, (g, tp, fp, fn, p, r, f) in rows.items():
        print(f"{k:13s} {g:5d} {tp:4d} {fp:4d} {fn:4d} {p:6.3f} {r:6.3f} {f:6.3f}")


if __name__ == "__main__":
    main()
