"""Per-document leak analysis on RedactionBench: where the no-leak rate goes.

Reads harness checkpoints (``--checkpoint-dir``) for one corpus split and, for
each system, reports how mandatory-span leaks are distributed over documents:
how many spans leak per document, whether leaks are whole misses or partial
(boundary) misses, how concentrated leaked characters are, and a coarse shape
breakdown of leaked spans. Only aggregate counts are written; no document text.

    python -m benchmarks.leak_analysis --ckpt-dir /root/bench-out/leak \
        --json research/results/raw/2026-10-11_redactionbench_test_leak_analysis.json
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from pathlib import Path
from typing import Any

from benchmarks import corpora


def _shape(s: str) -> str:
    # ponytail: coarse regex heuristic, not a type label (the corpus has none)
    s = s.strip()
    if "@" in s:
        return "contains @ (mostly passwords)"
    if re.fullmatch(r"[\d\s()+./:-]+", s):
        return "numeric (digits/punct)"
    if re.search(r"\d", s) and re.search(r"[A-Za-z]", s) and " " not in s:
        return "alphanumeric token"
    if re.fullmatch(r"[A-Z][\w'.-]*(\s+[A-Z][\w'.-]*)*", s):
        return "capitalised word(s)"
    if " " in s:
        return "multi-word phrase"
    return "other single token"


def analyse(docs: list[corpora.Doc], preds: list[list[list[int]]]) -> dict[str, Any]:
    per_doc = []
    spans_total = spans_full = spans_partial = spans_missed = 0
    chars_partial = chars_missed = 0
    shape_all: dict[str, int] = {}
    shape_leak: dict[str, int] = {}
    len_leak: list[int] = []
    len_ok: list[int] = []
    for doc, ps in zip(docs, preds, strict=True):
        mand = [g for g in doc.spans if g.necessity == "mandatory"]
        if not mand:
            continue
        n = len(doc.text)
        mask = bytearray(n)
        for s, e, *_ in ps:
            s, e = max(0, s), min(n, e)
            if e > s:
                mask[s:e] = b"\x01" * (e - s)
        leaked = 0
        for g in mand:
            cov = sum(mask[g.start : g.end])
            ln = g.end - g.start
            sh = _shape(doc.text[g.start : g.end])
            shape_all[sh] = shape_all.get(sh, 0) + 1
            spans_total += 1
            if cov == ln:
                spans_full += 1
                len_ok.append(ln)
                continue
            leaked += 1
            len_leak.append(ln)
            shape_leak[sh] = shape_leak.get(sh, 0) + 1
            if cov:
                spans_partial += 1
                chars_partial += ln - cov
            else:
                spans_missed += 1
                chars_missed += ln
        m_mask = bytearray(n)
        for g in mand:
            m_mask[g.start : g.end] = b"\x01" * (g.end - g.start)
        m_total = m_mask.count(1)
        m_leak = sum(1 for a, b in zip(m_mask, mask, strict=True) if a and not b)
        per_doc.append(
            {"spans": len(mand), "leaked_spans": leaked, "chars": m_total, "leaked_chars": m_leak}
        )

    nd = len(per_doc)
    leaked_counts = [d["leaked_spans"] for d in per_doc]
    leak_frac = [d["leaked_spans"] / d["spans"] for d in per_doc]
    lc = sorted((d["leaked_chars"] for d in per_doc), reverse=True)
    tot_lc = sum(lc)
    top10 = sum(lc[: max(1, nd // 10)])

    def q(xs: list[float]) -> list[float]:
        if not xs:
            return []
        xs = sorted(xs)
        return [xs[0], xs[len(xs) // 4], statistics.median(xs), xs[3 * len(xs) // 4], xs[-1]]

    return {
        "docs_with_mandatory": nd,
        "no_leak_docs": sum(1 for c in leaked_counts if c == 0),
        "docs_leaking_le": {k: sum(1 for c in leaked_counts if c <= k) for k in (0, 1, 2, 5, 10)},
        "docs_leaking_le_frac_spans": {
            str(f): sum(1 for x in leak_frac if x <= f) for f in (0.01, 0.05, 0.10, 0.25)
        },
        "leaked_spans_per_doc_min_q1_med_q3_max": q(leaked_counts),
        "leaked_span_fraction_per_doc_min_q1_med_q3_max": q(leak_frac),
        "mandatory_spans_per_doc_median": statistics.median(d["spans"] for d in per_doc),
        "spans": {
            "total": spans_total,
            "fully_redacted": spans_full,
            "partially_redacted": spans_partial,
            "missed": spans_missed,
        },
        "leaked_chars": {
            "total": tot_lc,
            "from_partial_spans": chars_partial,
            "from_missed_spans": chars_missed,
            "top_10pct_docs_share": top10 / tot_lc if tot_lc else 0.0,
        },
        "leaked_span_length_median": statistics.median(len_leak) if len_leak else None,
        "redacted_span_length_median": statistics.median(len_ok) if len_ok else None,
        "shape_heuristic": {
            k: {"spans": v, "leaked": shape_leak.get(k, 0), "leak_rate": shape_leak.get(k, 0) / v}
            for k, v in sorted(shape_all.items(), key=lambda kv: -kv[1])
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", default="redactionbench")
    ap.add_argument("--split", default="test")
    ap.add_argument("--ckpt-dir", type=Path, required=True)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    docs = corpora.load(args.corpus, args.split).docs
    out: dict[str, Any] = {"corpus": args.corpus, "split": args.split, "systems": {}}
    preds_by: dict[str, list] = {}
    for f in sorted(args.ckpt_dir.glob(f"{args.corpus}_{args.split}_*.json")):
        saved = json.loads(f.read_text(encoding="utf-8"))
        system = f.stem.removeprefix(f"{args.corpus}_{args.split}_")
        out["commit"] = saved["commit"]
        preds_by[system] = saved["run"]["preds"]
        out["systems"][system] = analyse(docs, preds_by[system])
    # oracle union of all systems: an upper bound on what combining them could reach
    union = [[x for p in preds_by.values() for x in p[i]] for i in range(len(docs))]
    out["systems"]["union-of-all"] = analyse(docs, union)
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    for s, r in out["systems"].items():
        print(
            f"{s:26} no-leak {r['no_leak_docs']}/{r['docs_with_mandatory']}  "
            f"<=1 {r['docs_leaking_le'][1]}  <=2 {r['docs_leaking_le'][2]}  "
            f"spans full/part/miss {r['spans']['fully_redacted']}/"
            f"{r['spans']['partially_redacted']}/{r['spans']['missed']}"
        )


if __name__ == "__main__":
    main()
