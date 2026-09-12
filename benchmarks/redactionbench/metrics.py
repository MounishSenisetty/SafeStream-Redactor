"""Rigorous scoring of SafeStream predictions against RedactionBench gold.

Three families of metric are computed, and the report keeps them clearly
separate because they answer different questions:

1. **Span-level detection (P / R / F1, TP / FP / FN)** — the standard NER-style
   metric. A prediction *hits* a gold span when it overlaps at least ``--overlap``
   (default 50%) of that gold span; matching is greedy and one-to-one so a single
   prediction cannot claim two golds. Reported **type-aware** (the predicted
   SafeStream type must equal the mapped gold type) and **type-agnostic** (any
   overlap counts, measuring "found *something* sensitive here" regardless of the
   label). This deliberately avoids exact-string comparison so partial and
   differently-bounded spans are credited.

2. **Character-level coverage (R-Score-style)** — RedactionBench's own metric,
   R-Score, is character-level and formatting-agnostic: it asks whether the right
   *characters* were hidden, not whether the replacement string matched. We
   reproduce that spirit with a character mask: mark every gold-redacted character
   and every predicted-redacted character, then score per-character
   precision/recall/F1 and accuracy. This nullifies masking-style differences
   (``[REDACTED]`` vs ``***`` vs ``<PHONE>``) exactly as R-Score intends. It is a
   faithful character-level *reimplementation of the R-Score methodology*, not a
   call into the paper's official scorer (which is not bundled); the report labels
   it as such.

3. **Dataset-level accuracy** — the fraction of documents whose predicted redaction
   mask exactly equals the gold mask (a "perfectly redacted document" rate). This
   is a per-document accuracy and is reported separately from precision/recall/F1,
   which are per-span/per-character rates.

Micro-averages pool counts across all types; macro-averages take the unweighted
mean of the per-type scores.
"""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass

# A scored span is reduced to (start, end, safestream_type).
Triple = tuple[int, int, str]


@dataclass(frozen=True)
class PRF:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def __add__(self, other: PRF) -> PRF:
        return PRF(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def overlap(a: tuple[int, int], b: tuple[int, int]) -> int:
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def span_hits(pred: tuple[int, int], gold: tuple[int, int], threshold: float) -> bool:
    """True when ``pred`` covers at least ``threshold`` of ``gold``.

    A zero-length gold span (start == end) is matched by any prediction that
    touches its position. ``threshold`` of 1.0 requires full coverage of gold;
    combine with an equal-length check for strict exact-boundary matching.
    """
    gold_len = gold[1] - gold[0]
    inter = overlap(pred, gold)
    if gold_len == 0:
        return pred[0] <= gold[0] <= pred[1]
    return inter >= threshold * gold_len


# ---------------------------------------------------------------------------
# span-level scoring
# ---------------------------------------------------------------------------


def score_type_aware(
    gold: list[Triple], preds: list[Triple], eval_types: set[str], threshold: float
) -> dict[str, PRF]:
    """Per-type (tp, fp, fn) restricted to ``eval_types``, greedy 1:1 matching."""
    gold_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in gold:
        if t in eval_types:
            gold_by_type[t].append((s, e))
    pred_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in preds:
        if t in eval_types:
            pred_by_type[t].append((s, e))

    out: dict[str, PRF] = {}
    for t in eval_types:
        golds = gold_by_type.get(t, [])
        matched: set[int] = set()
        tp = 0
        for ps, pe in pred_by_type.get(t, []):
            for i, g in enumerate(golds):
                if i not in matched and span_hits((ps, pe), g, threshold):
                    matched.add(i)
                    tp += 1
                    break
        fp = len(pred_by_type.get(t, [])) - tp
        fn = len(golds) - tp
        out[t] = PRF(tp, fp, fn)
    return out


def score_type_agnostic(
    gold: list[Triple], preds: list[Triple], eval_types: set[str], threshold: float
) -> PRF:
    """(tp, fp, fn) ignoring the label — did we flag the right *locations*?

    Restricted to gold spans of ``eval_types`` (categories SafeStream targets)
    and to predictions of any type, matched greedily by position only.
    """
    golds = [(s, e) for s, e, t in gold if t in eval_types]
    pred_spans = [(s, e) for s, e, _ in preds]
    matched: set[int] = set()
    tp = 0
    for ps, pe in pred_spans:
        for i, g in enumerate(golds):
            if i not in matched and span_hits((ps, pe), g, threshold):
                matched.add(i)
                tp += 1
                break
    fp = len(pred_spans) - tp
    fn = len(golds) - tp
    return PRF(tp, fp, fn)


# ---------------------------------------------------------------------------
# character-level scoring (R-Score-style)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CharCounts:
    tp: int  # chars redacted by both gold and prediction
    fp: int  # chars predicted-redacted but not gold
    fn: int  # chars gold-redacted but not predicted
    tn: int  # chars neither redacts

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    def __add__(self, other: CharCounts) -> CharCounts:
        return CharCounts(
            self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn
        )

    def as_dict(self) -> dict[str, float | int]:
        return {
            "char_tp": self.tp,
            "char_fp": self.fp,
            "char_fn": self.fn,
            "char_tn": self.tn,
            "char_precision": round(self.precision, 4),
            "char_recall": round(self.recall, 4),
            "char_f1": round(self.f1, 4),
            "char_accuracy": round(self.accuracy, 4),
        }


def char_mask(spans: list[tuple[int, int]], length: int) -> bytearray:
    mask = bytearray(length)
    for s, e in spans:
        s = max(0, s)
        e = min(length, e)
        for i in range(s, e):
            mask[i] = 1
    return mask


def score_chars(
    gold_spans: list[tuple[int, int]], pred_spans: list[tuple[int, int]], length: int
) -> CharCounts:
    g = char_mask(gold_spans, length)
    p = char_mask(pred_spans, length)
    tp = fp = fn = tn = 0
    for i in range(length):
        gi, pi = g[i], p[i]
        if gi and pi:
            tp += 1
        elif pi:
            fp += 1
        elif gi:
            fn += 1
        else:
            tn += 1
    return CharCounts(tp, fp, fn, tn)


# ---------------------------------------------------------------------------
# per-record scoring bundle
# ---------------------------------------------------------------------------


@dataclass
class RecordScore:
    doc_id: str
    type_aware: dict[str, PRF]
    type_agnostic: PRF
    chars_supported: CharCounts  # gold mask from mapped-type spans only
    chars_all_gold: CharCounts  # gold mask from ALL gold spans (honest coverage)
    exact_document: bool  # predicted mask == supported gold mask exactly
    n_gold: int
    n_gold_supported: int
    n_pred: int


def score_record(
    doc_id: str,
    text_len: int,
    gold_supported: list[Triple],
    gold_all: list[Triple],
    preds: list[Triple],
    eval_types: set[str],
    threshold: float,
) -> RecordScore:
    ta = score_type_aware(gold_supported, preds, eval_types, threshold)
    tag = score_type_agnostic(gold_supported, preds, eval_types, threshold)
    gold_sup_spans = [(s, e) for s, e, _ in gold_supported]
    gold_all_spans = [(s, e) for s, e, _ in gold_all]
    pred_spans = [(s, e) for s, e, _ in preds]
    chars_sup = score_chars(gold_sup_spans, pred_spans, text_len)
    chars_all = score_chars(gold_all_spans, pred_spans, text_len)
    exact = char_mask(gold_sup_spans, text_len) == char_mask(pred_spans, text_len)
    return RecordScore(
        doc_id=doc_id,
        type_aware=ta,
        type_agnostic=tag,
        chars_supported=chars_sup,
        chars_all_gold=chars_all,
        exact_document=exact,
        n_gold=len(gold_all),
        n_gold_supported=len(gold_supported),
        n_pred=len(preds),
    )


# ---------------------------------------------------------------------------
# corpus aggregation
# ---------------------------------------------------------------------------


@dataclass
class Aggregate:
    per_type: dict[str, PRF]
    micro: PRF
    macro_f1: float
    type_agnostic: PRF
    chars_supported: CharCounts
    chars_all_gold: CharCounts
    dataset_accuracy: float  # fraction of documents redacted exactly right
    documents: int
    f1_ci: tuple[float, float, float] = (0.0, 0.0, 0.0)  # point, lo, hi


def aggregate(scores: list[RecordScore], eval_types: set[str]) -> Aggregate:
    per_type: dict[str, PRF] = {t: PRF(0, 0, 0) for t in eval_types}
    for sc in scores:
        for t, prf in sc.type_aware.items():
            per_type[t] = per_type[t] + prf
    micro = PRF(0, 0, 0)
    for prf in per_type.values():
        micro = micro + prf
    macro_f1 = sum(prf.f1 for prf in per_type.values()) / len(per_type) if per_type else 0.0
    tag = PRF(0, 0, 0)
    chars_sup = CharCounts(0, 0, 0, 0)
    chars_all = CharCounts(0, 0, 0, 0)
    exact = 0
    for sc in scores:
        tag = tag + sc.type_agnostic
        chars_sup = chars_sup + sc.chars_supported
        chars_all = chars_all + sc.chars_all_gold
        exact += 1 if sc.exact_document else 0
    return Aggregate(
        per_type=per_type,
        micro=micro,
        macro_f1=macro_f1,
        type_agnostic=tag,
        chars_supported=chars_sup,
        chars_all_gold=chars_all,
        dataset_accuracy=exact / len(scores) if scores else 0.0,
        documents=len(scores),
        f1_ci=bootstrap_micro_f1_ci(scores, eval_types),
    )


def bootstrap_micro_f1_ci(
    scores: list[RecordScore],
    eval_types: set[str],
    *,
    resamples: int = 1000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Point micro-F1 and a bootstrap CI, resampling whole documents.

    Documents (not spans) are the resampling unit so the tp/fp/fn coupling
    within a document is preserved — the interval a reviewer expects beside a
    headline F1.
    """

    def micro_f1(sample: list[RecordScore]) -> float:
        agg = PRF(0, 0, 0)
        for sc in sample:
            for t in eval_types:
                agg = agg + sc.type_aware.get(t, PRF(0, 0, 0))
        return agg.f1

    point = micro_f1(scores)
    if len(scores) < 2 or resamples <= 0:
        return point, point, point
    rng = random.Random(seed)
    n = len(scores)
    stats = sorted(micro_f1([scores[rng.randrange(n)] for _ in range(n)]) for _ in range(resamples))
    lo = stats[int((alpha / 2) * resamples)]
    hi = stats[min(resamples - 1, int((1 - alpha / 2) * resamples))]
    return point, lo, hi
