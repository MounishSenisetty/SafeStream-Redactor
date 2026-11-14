"""Second-annotator agreement for the Loghub template-slot labels.

The gold of the real-log corpora (``loghub_ssh``, ``loghub_linux``) comes from one
label per template slot (``HOST``, ``USER`` or none) plus account names written
literally into a template; the labels were drafted from the template text and
checked by one author. This script lets a second person label the same templates
blind and measures agreement with the frozen labels.

    python -m benchmarks.loghub_agreement sheet -o second_annotator.csv
        (a ready copy is committed as benchmarks/corpora/loghub_second_annotator_sheet.csv)
        Writes a blind labelling sheet: every template of both corpora, one row per
        <*> slot plus one ``literal`` row per template, with the template text only.
        It contains none of the frozen labels.

    python -m benchmarks.loghub_agreement agree second_annotator.csv --annotator NAME
        Compares the filled sheet with the frozen labels: Cohen's kappa over slots
        (HOST / USER / none) with 95% intervals from resampling templates, agreement
        on literal account names, and line-level agreement on the gold spans each
        labelling produces (exact span F1, share of lines with identical gold). Lists
        every disagreement for adjudication. Writes a JSON result.

The frozen labels are not changed by this script, whatever the agreement: the
paper reports agreement next to the results scored on the frozen labels.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from benchmarks import corpora
from benchmarks.cluster_bootstrap import weight_matrix

CLASSES = ("none", "HOST", "USER")
_IDX = {c: i for i, c in enumerate(CLASSES)}
CORPORA = {
    "loghub_ssh": ("OpenSSH", corpora.LOGHUB_SLOTS, "ssh", False),
    "loghub_linux": ("Linux", corpora.LOGHUB_SLOTS_LINUX, "linux", True),
}
FIELDS = ["corpus", "template_id", "slot", "template", "label"]

INSTRUCTIONS = """\
# Second-annotator sheet for the Loghub template labels. Work alone and do not open
# benchmarks/corpora/loghub_slots*.json or the paper's results before you finish.
# For each row with slot = 1, 2, ...: the slot is the <*> marked [[<*>]] in the
# template. Write in 'label':
#   HOST  if the slot holds the remote host or address a connection or login came from
#   USER  if the slot holds an account (user) name
#   (leave empty) for anything else: ports, uids, pids, counts, ttys, services, ...
# For each row with slot = literal: list account names written literally in the
# template text (not in a slot), separated by ';', or leave it empty.
# Lines starting with '#' are ignored.
"""


def _templates(system: str) -> list[tuple[str, str]]:
    path = corpora.EXTERNAL / "loghub" / system / f"{system}_2k.log_templates.csv"
    with path.open(encoding="utf-8", errors="replace", newline="") as f:
        return [(r["EventId"], r["EventTemplate"]) for r in csv.DictReader(f)]


def _mark(template: str, k: int) -> str:
    """The template with its k-th <*> (1-based) shown as [[<*>]]."""
    parts = template.split("<*>")
    return "".join(
        p + ("" if i == len(parts) - 1 else ("[[<*>]]" if i + 1 == k else "<*>"))
        for i, p in enumerate(parts)
    )


def write_sheet(out: Path) -> int:
    rows = 0
    with out.open("w", encoding="utf-8", newline="") as f:
        f.write(INSTRUCTIONS)
        w = csv.writer(f)
        w.writerow(FIELDS)
        for name, (system, _p, _x, _u) in CORPORA.items():
            for tid, template in _templates(system):
                for k in range(1, template.count("<*>") + 1):
                    w.writerow([name, tid, k, _mark(template, k), ""])
                    rows += 1
                w.writerow([name, tid, "literal", template, ""])
                rows += 1
    return rows


def read_sheet(path: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """corpus -> template id -> {"slots": [...], "literal_users": [...]}, as in the JSON."""
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    out: dict[str, dict[str, dict[str, Any]]] = {c: {} for c in CORPORA}
    for row in csv.DictReader(lines):
        corpus, tid, slot = row["corpus"], row["template_id"], row["slot"]
        label = (row.get("label") or "").strip()
        entry = out[corpus].setdefault(tid, {"slots": [], "literal_users": []})
        if slot == "literal":
            entry["literal_users"] = sorted({u.strip() for u in label.split(";") if u.strip()})
            continue
        if label.upper() not in ("", "HOST", "USER"):
            raise ValueError(f"{corpus} {tid} slot {slot}: label must be HOST, USER or empty")
        k = int(slot)
        while len(entry["slots"]) < k:
            entry["slots"].append(None)
        entry["slots"][k - 1] = label.upper() or None
    return out


def kappa(confusion: np.ndarray) -> float:
    """Cohen's kappa from a square confusion matrix (rows: first, columns: second)."""
    n = confusion.sum()
    if n == 0:
        return float("nan")
    po = np.trace(confusion) / n
    pe = float(confusion.sum(1) @ confusion.sum(0)) / (n * n)
    return 1.0 if pe == 1 else float((po - pe) / (1 - pe))


def slot_pairs(
    first: dict[str, dict[str, Any]], second: dict[str, dict[str, Any]], templates: list[str]
) -> list[tuple[str, int, int]]:
    """(template id, first class, second class) for every slot of every template."""
    pairs = []
    for tid in templates:
        a = (first.get(tid) or {}).get("slots", [])
        b = (second.get(tid) or {}).get("slots", [])
        for k in range(max(len(a), len(b))):
            x = a[k] if k < len(a) else None
            y = b[k] if k < len(b) else None
            pairs.append((tid, _IDX[x or "none"], _IDX[y or "none"]))
    return pairs


def kappa_with_interval(
    pairs: list[tuple[str, int, int]], resamples: int = 2000, seed: int = 0
) -> dict[str, Any]:
    labels = [t for t, _a, _b in pairs]
    cells = np.zeros((len(pairs), len(CLASSES) ** 2))
    for i, (_t, a, b) in enumerate(pairs):
        cells[i, a * len(CLASSES) + b] = 1
    conf = cells.sum(0).reshape(len(CLASSES), len(CLASSES))
    w = weight_matrix("cluster", labels, resamples, seed)
    draws = [kappa((wr @ cells).reshape(len(CLASSES), len(CLASSES))) for wr in w]
    lo, hi = np.nanpercentile(draws, [2.5, 97.5])
    return {
        "slots": len(pairs),
        "templates": len(set(labels)),
        "observed_agreement": float(np.trace(conf) / conf.sum()) if conf.sum() else None,
        "kappa": kappa(conf),
        "kappa_95ci_templates": [float(lo), float(hi)],
        "confusion_first_rows_second_cols": {
            CLASSES[i]: {CLASSES[j]: int(conf[i, j]) for j in range(len(CLASSES))}
            for i in range(len(CLASSES))
        },
    }


def span_agreement(docs_a: list[Any], docs_b: list[Any]) -> dict[str, Any]:
    """Exact span agreement (offsets and type) between two gold labellings of the same lines."""
    by_id = {d.doc_id: d for d in docs_b}
    m = na = nb = same_lines = 0
    per_type: Counter[str] = Counter()
    tot_type: Counter[str] = Counter()
    for d in docs_a:
        e = by_id.get(d.doc_id)
        sa = {(g.start, g.end, g.type) for g in d.spans}
        sb = {(g.start, g.end, g.type) for g in e.spans} if e else set()
        inter = sa & sb
        m, na, nb = m + len(inter), na + len(sa), nb + len(sb)
        same_lines += int(sa == sb)
        for _s, _e, t in inter:
            per_type[t] += 2
        for _s, _e, t in sa:
            tot_type[t] += 1
        for _s, _e, t in sb:
            tot_type[t] += 1
    return {
        "lines": len(docs_a),
        "lines_with_identical_gold": same_lines,
        "share_identical": same_lines / len(docs_a) if docs_a else None,
        "spans_first": na,
        "spans_second": nb,
        "span_f1_exact": 2 * m / (na + nb) if na + nb else 1.0,
        "span_f1_exact_by_type": {t: per_type[t] / tot_type[t] for t in sorted(tot_type)},
    }


def _lines(system: str) -> tuple[list[dict[str, str]], list[str]]:
    d = corpora.EXTERNAL / "loghub" / system
    lines = (d / f"{system}_2k.log").read_text(encoding="utf-8", errors="replace").splitlines()
    with (d / f"{system}_2k.log_structured.csv").open(
        encoding="utf-8", errors="replace", newline=""
    ) as f:
        return list(csv.DictReader(f)), lines


def agree(sheet: Path, annotator: str, resamples: int = 2000, seed: int = 0) -> dict[str, Any]:
    second = read_sheet(sheet)
    result: dict[str, Any] = {
        "annotator": annotator,
        "sheet": sheet.name,
        "date": dt.date.today().isoformat(),
        "resamples": resamples,
        "seed": seed,
        "corpora": {},
    }
    all_pairs: list[tuple[str, int, int]] = []
    for name, (system, path, prefix, unlisted) in CORPORA.items():
        frozen = json.loads(path.read_text(encoding="utf-8"))
        if annotator.strip().lower() == str(frozen.get("verified_by", "")).strip().lower():
            raise ValueError("the second annotator must not be the person who verified the labels")
        first = frozen[system]
        templates = [t for t, _ in _templates(system)]
        missing = [t for t in templates if t not in second[name]]
        if missing:
            raise ValueError(f"{name}: sheet has no rows for templates {missing[:5]}...")
        pairs = slot_pairs(first, second[name], templates)
        all_pairs += [(f"{name}:{t}", a, b) for t, a, b in pairs]
        lit = [
            (
                t,
                sorted((first.get(t) or {}).get("literal_users", [])),
                sorted(second[name][t].get("literal_users", [])),
            )
            for t in templates
        ]
        structured, lines = _lines(system)
        docs_a, _ = corpora.loghub_ssh_gold(first, structured, lines, prefix, unlisted)
        docs_b, _ = corpora.loghub_ssh_gold(second[name], structured, lines, prefix, unlisted)
        result["corpora"][name] = {
            "slots": kappa_with_interval(pairs, resamples, seed),
            "literal_names": {
                "templates_agreeing": sum(a == b for _t, a, b in lit),
                "templates": len(lit),
            },
            "lines": span_agreement(docs_a, docs_b),
            "disagreements": [
                {"template": t, "slot": k, "first": CLASSES[a], "second": CLASSES[b]}
                for t, (k, a, b) in _numbered(pairs)
                if a != b
            ]
            + [
                {"template": t, "slot": "literal", "first": a, "second": b}
                for t, a, b in lit
                if a != b
            ],
        }
    result["pooled_slots"] = kappa_with_interval(all_pairs, resamples, seed)
    return result


def _numbered(pairs: list[tuple[str, int, int]]) -> list[tuple[str, tuple[int, int, int]]]:
    out, seen = [], Counter()
    for t, a, b in pairs:
        seen[t] += 1
        out.append((t, (seen[t], a, b)))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmarks.loghub_agreement")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sheet", help="write the blind labelling sheet")
    s.add_argument("-o", "--out", type=Path, default=Path("loghub_second_annotator.csv"))
    a = sub.add_parser("agree", help="agreement of a filled sheet with the frozen labels")
    a.add_argument("sheet", type=Path)
    a.add_argument("--annotator", required=True, help="name of the second annotator")
    a.add_argument("--resamples", type=int, default=2000)
    a.add_argument("--seed", type=int, default=0)
    a.add_argument("-o", "--out", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "sheet":
        n = write_sheet(args.out)
        print(f"wrote {n} rows to {args.out}")
        return 0
    res = agree(args.sheet, args.annotator, args.resamples, args.seed)
    stem = re.sub(r"\W+", "-", args.annotator.lower()).strip("-")
    out = args.out or (
        corpora.ROOT
        / "research"
        / "results"
        / "raw"
        / f"{res['date']}_loghub_second_annotator_{stem}.json"
    )
    out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    for name, r in res["corpora"].items():
        k = r["slots"]
        print(
            f"{name}: slot kappa {k['kappa']:.3f} [{k['kappa_95ci_templates'][0]:.3f}, "
            f"{k['kappa_95ci_templates'][1]:.3f}] over {k['slots']} slots; span F1 "
            f"{r['lines']['span_f1_exact']:.3f}; {len(r['disagreements'])} disagreements"
        )
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
