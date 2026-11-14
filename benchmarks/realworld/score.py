"""Score harness runs on the real-world corpus.

Outputs, all without document text:

* the harness metrics (character P/R/F1, fully redacted rate, false-alarm rate,
  mandatory recall, no-leak document rate) per system, with document, cluster and
  two-stage (by source) intervals and paired differences on one resample matrix;
* per gold type, and per ``type:subtype`` where annotators gave one, the number of
  spans, the share fully redacted and the character recall, with two-stage
  intervals;
* leaked mandatory spans (not fully redacted) per system and type, with the
  documents they occur in, for zero-tolerance acceptance criteria;
* LaTeX tables for the manuscript (they use the ``\\pc`` macro of
  ``paper/journal/content/preamble.tex``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
from benchmarks import harness
from benchmarks.cluster_bootstrap import bootstrap, weight_matrix
from benchmarks.realworld.data import Dataset, Span

Pred = harness.Pred


def _keys(span: Span) -> list[str]:
    return [span.type, f"{span.type}:{span.subtype}"] if span.subtype else [span.type]


def type_counts(gold: Sequence[Span], preds: Sequence[Pred], n: int) -> dict[str, float]:
    """Additive per-type coverage counters for one document."""
    mask = np.zeros(n, dtype=bool)
    for s, e, _t in preds:
        mask[max(0, s) : min(n, e)] = True
    c: dict[str, float] = {}
    for g in gold:
        covered = int(mask[g.start : g.end].sum())
        for k in _keys(g):
            c[f"{k}|spans"] = c.get(f"{k}|spans", 0) + 1
            c[f"{k}|full"] = c.get(f"{k}|full", 0) + int(covered == g.end - g.start)
            c[f"{k}|chars"] = c.get(f"{k}|chars", 0) + g.end - g.start
            c[f"{k}|covered"] = c.get(f"{k}|covered", 0) + covered
    return c


def leaks(
    ds: Dataset, preds: Sequence[Sequence[Pred]], credential_types: frozenset[str]
) -> dict[str, Any]:
    """Mandatory spans not fully redacted, by type, with their documents."""
    assert ds.adjudicated is not None
    by_type: dict[str, dict[str, Any]] = {}
    for doc, ps in zip(ds.documents, preds, strict=True):
        mask = np.zeros(len(doc.text), dtype=bool)
        for s, e, _t in ps:
            mask[max(0, s) : min(len(doc.text), e)] = True
        for g in ds.adjudicated[doc.doc_id]:
            if g.necessity != "mandatory" or mask[g.start : g.end].all():
                continue
            for k in _keys(g):
                row = by_type.setdefault(k, {"leaked_spans": 0, "docs": set()})
                row["leaked_spans"] += 1
                row["docs"].add(doc.doc_id)
    out = {
        k: {"leaked_spans": v["leaked_spans"], "docs": sorted(v["docs"])}
        for k, v in by_type.items()
    }
    out["_credential_leaks"] = sum(
        v["leaked_spans"] for k, v in by_type.items() if k in credential_types
    )
    return out


def per_type(
    ds: Dataset,
    preds: dict[str, Sequence[Sequence[Pred]]],
    labels: list[str],
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    assert ds.adjudicated is not None
    w = weight_matrix("two_stage", labels, resamples, seed)
    out: dict[str, Any] = {}
    for name, ps in preds.items():
        rows = [
            type_counts(ds.adjudicated[d.doc_id], p, len(d.text))
            for d, p in zip(ds.documents, ps, strict=True)
        ]
        keys = sorted({k for r in rows for k in r})
        mat = np.array([[r.get(k, 0) for k in keys] for r in rows], float)
        col = {k: i for i, k in enumerate(keys)}
        total, sums = mat.sum(0), w @ mat
        res = {}
        for t in sorted({k.split("|")[0] for k in keys}):
            sp, fu = col[f"{t}|spans"], col[f"{t}|full"]
            ch, cv = col[f"{t}|chars"], col[f"{t}|covered"]
            fr = np.divide(
                sums[:, fu], sums[:, sp], out=np.full(len(sums), np.nan), where=sums[:, sp] > 0
            )
            cr = np.divide(
                sums[:, cv], sums[:, ch], out=np.full(len(sums), np.nan), where=sums[:, ch] > 0
            )
            res[t] = {
                "spans": int(total[sp]),
                "fully_redacted": float(total[fu] / total[sp]),
                "char_recall": float(total[cv] / total[ch]),
                "ci95_two_stage": {
                    "fully_redacted": [float(np.nanpercentile(fr, q)) for q in (2.5, 97.5)],
                    "char_recall": [float(np.nanpercentile(cr, q)) for q in (2.5, 97.5)],
                },
            }
        out[name] = res
    return out


def score(
    ds: Dataset,
    preds: dict[str, Sequence[Sequence[Pred]]],
    pairs: list[tuple[str, str]],
    labels: list[str],
    credential_types: frozenset[str] = frozenset({"SECRET"}),
    resamples: int = 2000,
    seed: int = 0,
) -> dict[str, Any]:
    from benchmarks.realworld.data import to_corpus

    corpus = to_corpus(ds)
    res = bootstrap(
        corpus.docs, labels, {k: list(v) for k, v in preds.items()}, pairs, resamples, seed
    )
    return {
        "n_docs": len(corpus.docs),
        "n_clusters": len(set(labels)),
        "resamples": resamples,
        "seed": seed,
        **res,
        "per_type": per_type(ds, preds, labels, resamples, seed),
        "leaks": {n: leaks(ds, p, credential_types) for n, p in preds.items()},
    }


def _f(x: float) -> str:
    return f"{x:.3f}".replace("0.", ".", 1)


def _d(x: float) -> str:
    return f"{x:+.3f}".replace("0.", ".", 1)


def latex_main(result: dict[str, Any], names: dict[str, str]) -> str:
    """Systems x metrics with two-stage intervals, stacked with ``\\pc``."""
    cols = [
        ("char_p", "Char P"),
        ("char_r", "Char R"),
        ("char_f1", "Char F1"),
        ("entity_recall_covered", "FR"),
        ("no_leak_doc_rate", "No-leak docs"),
    ]
    lines = [
        r"\begin{tabular*}{\textwidth}{@{\extracolsep\fill}l" + "l" * len(cols) + "}",
        r"\toprule",
        "System & " + " & ".join(c for _k, c in cols) + r" \\",
        r"\midrule",
    ]
    for key, label in names.items():
        pt, ci = result["point"][key], result["ci95"]["two_stage"][key]
        cells = [rf"\pc{{{_f(pt[k])}}}{{{_f(ci[k][0])}, {_f(ci[k][1])}}}" for k, _c in cols]
        lines.append(f"{label} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular*}"]
    return "\n".join(lines) + "\n"


def latex_pairs(result: dict[str, Any], names: dict[str, str]) -> str:
    """Paired differences under the three schemes; a dagger marks an interval with zero."""
    lines = [
        r"\begin{tabular*}{\textwidth}{@{\extracolsep\fill}lllll}",
        r"\toprule",
        r"Comparison & Metric & Document & Cluster & Two-stage \\",
        r"\midrule",
    ]
    metrics = [("entity_recall_covered", "FR"), ("char_f1", "Char F1")]
    for pair in result["paired_diff_p2.5_p50_p97.5"]["document"]:
        a, b = pair.split(" - ")
        for key, label in metrics:
            cells = []
            for scheme in ("document", "cluster", "two_stage"):
                lo, m, hi = result["paired_diff_p2.5_p50_p97.5"][scheme][pair][key]
                mark = r"\ns" if lo <= 0 <= hi else ""
                cells.append(rf"\pc{{${_d(m)}${mark}}}{{${_d(lo)}$, ${_d(hi)}$}}")
            lines.append(
                f"{names.get(a, a)} $-$ {names.get(b, b)} & {label} & " + " & ".join(cells) + r" \\"
            )
    lines += [r"\bottomrule", r"\end{tabular*}"]
    return "\n".join(lines) + "\n"


def latex_types(result: dict[str, Any], names: dict[str, str], min_spans: int = 1) -> str:
    """Gold types x systems: fully redacted share with two-stage intervals."""
    first = next(iter(names))
    types = [t for t, v in sorted(result["per_type"][first].items()) if v["spans"] >= min_spans]
    lines = [
        r"\begin{tabular*}{\textwidth}{@{\extracolsep\fill}lr" + "l" * len(names) + "}",
        r"\toprule",
        "Gold type & Spans & " + " & ".join(names.values()) + r" \\",
        r"\midrule",
    ]
    for t in types:
        cells = []
        for key in names:
            v = result["per_type"][key][t]
            lo, hi = v["ci95_two_stage"]["fully_redacted"]
            cells.append(rf"\pc{{{_f(v['fully_redacted'])}}}{{{_f(lo)}, {_f(hi)}}}")
        label = t.replace("_", r"\_")
        lines.append(
            f"{label} & {result['per_type'][first][t]['spans']} & " + " & ".join(cells) + r" \\"
        )
    lines += [r"\bottomrule", r"\end{tabular*}"]
    return "\n".join(lines) + "\n"
