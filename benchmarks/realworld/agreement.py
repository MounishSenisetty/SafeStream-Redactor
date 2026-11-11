"""Inter-annotator agreement for the real-world corpus.

For each pair of annotators:

* **character kappa, binary**: Cohen's kappa over characters labelled sensitive or
  not, pooled over documents;
* **character kappa, typed**: the same with the canonical type as the label;
* **span F1, exact**: one-to-one matches with identical offsets (and type), as
  ``2m / (|A| + |B|)``;
* **span F1, overlap**: one-to-one greedy matches of spans that share at least one
  character, regardless of type, and the share of those matches whose types agree;
* the same span F1 per canonical type.

Kappa and span F1 are built from additive per-document counts, so each comes with
95% bootstrap intervals over documents and over sources (two-stage), on one
shared resample matrix (2,000 resamples, seed 0 by default).
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from typing import Any

import numpy as np
from benchmarks.cluster_bootstrap import weight_matrix
from benchmarks.realworld.data import TYPES, Dataset, Span

LABELS = ["O", *sorted(TYPES)]
_INDEX = {lab: i for i, lab in enumerate(LABELS)}


def _char_labels(spans: Sequence[Span], n: int) -> np.ndarray:
    lab = np.zeros(n, dtype=np.int64)
    for s in spans:
        lab[s.start : s.end] = _INDEX[s.type]
    return lab


def _overlap_matches(a: Sequence[Span], b: Sequence[Span]) -> tuple[int, int]:
    """(matched pairs, matched pairs with the same type), one-to-one, greedy in order."""
    used: set[int] = set()
    m = same = 0
    for x in a:
        for k, y in enumerate(b):
            if k not in used and min(x.end, y.end) > max(x.start, y.start):
                used.add(k)
                m += 1
                same += int(x.type == y.type)
                break
    return m, same


def doc_counts(a: Sequence[Span], b: Sequence[Span], n: int) -> dict[str, float]:
    """Additive agreement counters for one document."""
    la, lb = _char_labels(a, n), _char_labels(b, n)
    k = len(LABELS)
    typed = np.bincount(la * k + lb, minlength=k * k).astype(float)
    ba, bb = la > 0, lb > 0
    c: dict[str, float] = {
        "bin_11": float(np.sum(ba & bb)),
        "bin_10": float(np.sum(ba & ~bb)),
        "bin_01": float(np.sum(~ba & bb)),
        "bin_00": float(np.sum(~ba & ~bb)),
        "spans_a": len(a),
        "spans_b": len(b),
    }
    c |= {f"typed_{i}": v for i, v in enumerate(typed)}
    exact = {(s.start, s.end, s.type) for s in a} & {(s.start, s.end, s.type) for s in b}
    c["exact"] = len(exact)
    c["overlap"], c["overlap_same_type"] = _overlap_matches(a, b)
    for t in TYPES:
        at = [s for s in a if s.type == t]
        bt = [s for s in b if s.type == t]
        c[f"{t}|a"], c[f"{t}|b"] = len(at), len(bt)
        c[f"{t}|exact"] = len({(s.start, s.end) for s in at} & {(s.start, s.end) for s in bt})
        c[f"{t}|overlap"] = _overlap_matches(at, bt)[0]
    return c


def _kappa_binary(g: Any) -> Any:
    n = g("bin_11") + g("bin_10") + g("bin_01") + g("bin_00")
    po = (g("bin_11") + g("bin_00")) / n
    pa1, pb1 = (g("bin_11") + g("bin_10")) / n, (g("bin_11") + g("bin_01")) / n
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    return np.divide(po - pe, 1 - pe, out=np.ones_like(np.asarray(po, float)), where=(1 - pe) > 0)


def _kappa_typed(g: Any) -> Any:
    k = len(LABELS)
    m = np.stack([g(f"typed_{i}") for i in range(k * k)], axis=-1)
    m = m.reshape(*m.shape[:-1], k, k)
    n = m.sum(axis=(-2, -1))
    po = np.trace(m, axis1=-2, axis2=-1) / n
    pe = (m.sum(axis=-1) * m.sum(axis=-2)).sum(axis=-1) / n**2
    return np.divide(po - pe, 1 - pe, out=np.ones_like(np.asarray(po, float)), where=(1 - pe) > 0)


def _f1(g: Any, hits: str, a: str = "spans_a", b: str = "spans_b") -> Any:
    den = g(a) + g(b)
    return np.divide(2 * g(hits), den, out=np.ones_like(np.asarray(den, float)), where=den > 0)


def metrics(g: Any) -> dict[str, Any]:
    out = {
        "char_kappa_binary": _kappa_binary(g),
        "char_kappa_typed": _kappa_typed(g),
        "span_f1_exact": _f1(g, "exact"),
        "span_f1_overlap": _f1(g, "overlap"),
    }
    m = np.asarray(g("overlap"), float)
    out["type_agreement_on_overlaps"] = np.divide(
        g("overlap_same_type"), m, out=np.ones_like(m), where=m > 0
    )
    return out


def agreement(
    ds: Dataset, labels: list[str], resamples: int = 2000, seed: int = 0
) -> dict[str, Any]:
    """Pairwise agreement with document-level and two-stage (by source) intervals."""
    texts = {d.doc_id: d.text for d in ds.documents}
    ids = [d.doc_id for d in ds.documents]
    weights = {s: weight_matrix(s, labels, resamples, seed) for s in ("document", "two_stage")}
    out: dict[str, Any] = {"n_docs": len(ids), "resamples": resamples, "seed": seed, "pairs": {}}
    for a, b in itertools.combinations(sorted(ds.annotations), 2):
        rows = [doc_counts(ds.annotations[a][i], ds.annotations[b][i], len(texts[i])) for i in ids]
        keys = sorted(rows[0]) if rows else []
        col = {k: j for j, k in enumerate(keys)}
        mat = np.array([[r[k] for k in keys] for r in rows], float)
        total = mat.sum(0)
        point = {k: float(v) for k, v in metrics(lambda key, t=total, c=col: t[c[key]]).items()}
        ci = {}
        for scheme, w in weights.items():
            sums = w @ mat
            boot = metrics(lambda key, s=sums, c=col: s[:, c[key]])
            ci[scheme] = {
                k: [float(np.nanpercentile(v, 2.5)), float(np.nanpercentile(v, 97.5))]
                for k, v in boot.items()
            }
        per_type = {}
        for t in sorted(TYPES):
            na, nb = total[col[f"{t}|a"]], total[col[f"{t}|b"]]
            if na + nb == 0:
                continue
            per_type[t] = {
                "spans_a": int(na),
                "spans_b": int(nb),
                "span_f1_exact": float(2 * total[col[f"{t}|exact"]] / (na + nb)),
                "span_f1_overlap": float(2 * total[col[f"{t}|overlap"]] / (na + nb)),
            }
        out["pairs"][f"{a} vs {b}"] = {"point": point, "ci95": ci, "per_type": per_type}
    return out
