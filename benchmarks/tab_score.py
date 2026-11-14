"""Score harness checkpoints on TAB (Text Anonymization Benchmark) as TAB prescribes.

Protocol, fixed before any system was run on TAB (see PROTOCOL below; the commit
that adds this file precedes every TAB checkpoint):

* Data: TAB's test split only (127 ECHR judgments). No SafeStream rule, threshold
  or configuration was developed or chosen with TAB in view, and none is changed
  after scoring.
* Gold: per annotator, the mentions whose identifier type is DIRECT or QUASI (TAB's
  masking decision). Documents annotated by several people are scored against each
  annotator separately and the counts pooled, as in TAB's own evaluation.
* Metrics (type-agnostic: a character is protected whatever label it receives):
  - char recall: masked gold characters / gold characters, pooled over
    (document, annotator) pairs;
  - char precision: redacted characters that some annotator marked DIRECT or QUASI
    / redacted characters (TAB counts a masked token as correct if any annotator
    masked it); char F1 from these two;
  - entity recall, direct and quasi (TAB's ER_di, ER_qi): for each annotator, an
    entity's DIRECT (QUASI) mentions are grouped by entity id, and the entity is
    protected only if every one of those mentions is fully redacted;
  - direct-protected rate: share of (document, annotator) pairs in which every
    DIRECT mention is fully redacted;
  - char recall by TAB entity type (descriptive, no intervals).
  TAB's information-weighted precision is not computed (it needs a language
  model); precision here is unweighted.
* Intervals: 95% percentile bootstrap over documents, 2,000 resamples, seed 0, one
  shared resample matrix for all systems, so differences are paired.
* Planned comparisons: SafeStream +spaCy minus Presidio sm (same spaCy model) and
  minus Presidio lg, and SafeStream pattern minus Presidio regex, each on char F1,
  char recall and direct entity recall. Every other difference is descriptive.

    python -m benchmarks.tab_score --system NAME=CHECKPOINT ... --json OUT
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from benchmarks import corpora
from benchmarks.cluster_bootstrap import load_checkpoint, weight_matrix

PROTOCOL = __doc__
PLANNED = [
    ("safestream+spacy", "presidio-sm"),
    ("safestream+spacy", "presidio-lg"),
    ("safestream-pattern", "presidio-regex"),
]
PLANNED_METRICS = ("char_f1", "char_recall", "er_direct")
_KEYS = (
    "gold",
    "gold_hit",
    "red",
    "red_ok",
    "ent_d",
    "ent_d_ok",
    "ent_q",
    "ent_q_ok",
    "pairs_d",
    "pairs_d_ok",
)


def _mask(spans: list[tuple[int, int]], n: int) -> np.ndarray:
    m = np.zeros(n, dtype=bool)
    for a, b in spans:
        m[max(a, 0) : min(b, n)] = True
    return m


def doc_counts(doc: dict[str, Any], preds: list[tuple[int, ...]]) -> tuple[dict[str, float], dict]:
    """Additive counts for one document, and per-type (gold, hit) character counts."""
    n = len(doc["text"])
    red = _mask([(p[0], p[1]) for p in preds], n)
    per_ann = corpora.tab_annotations(doc)
    union = np.zeros(n, dtype=bool)
    c = dict.fromkeys(_KEYS, 0.0)
    by_type: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for mentions in per_ann.values():
        g = _mask([(a, b) for a, b, *_ in mentions], n)
        union |= g
        c["gold"] += g.sum()
        c["gold_hit"] += (g & red).sum()
        ents: dict[tuple[str, str], bool] = {}
        all_direct = True
        has_direct = False
        for a, b, etype, ident, ent in mentions:
            full = bool(red[a:b].all())
            key = (ident, ent)
            ents[key] = ents.get(key, True) and full
            gt = _mask([(a, b)], n)
            by_type[etype][0] += gt.sum()
            by_type[etype][1] += (gt & red).sum()
            if ident == "DIRECT":
                has_direct = True
                all_direct = all_direct and full
        for (ident, _e), ok in ents.items():
            k = "ent_d" if ident == "DIRECT" else "ent_q"
            c[k] += 1
            c[k + "_ok"] += ok
        if has_direct:
            c["pairs_d"] += 1
            c["pairs_d_ok"] += all_direct
    c["red"] = float(red.sum())
    c["red_ok"] = float((red & union).sum())
    return c, by_type


def metrics(v: np.ndarray) -> dict[str, np.ndarray]:
    k = {key: v[..., i] for i, key in enumerate(_KEYS)}

    def div(a, b):
        return np.divide(a, b, out=np.zeros_like(a, dtype=float), where=b > 0)

    p, r = div(k["red_ok"], k["red"]), div(k["gold_hit"], k["gold"])
    return {
        "char_precision": p,
        "char_recall": r,
        "char_f1": div(2 * p * r, p + r),
        "er_direct": div(k["ent_d_ok"], k["ent_d"]),
        "er_quasi": div(k["ent_q_ok"], k["ent_q"]),
        "direct_protected": div(k["pairs_d_ok"], k["pairs_d"]),
    }


CORPUS_FILES = {
    "tab": ("tab", "echr_test.json", "test"),
    "tab_dev": ("tab", "echr_dev.json", "dev"),
    "tab_train": ("tab", "echr_train.json", "test"),
    "wiki_bios": ("wiki_bios", "annotated_wikipedia.json", "test"),
}


def score(
    systems: dict[str, list[list[tuple[int, ...]]]],
    resamples: int = 2000,
    seed: int = 0,
    corpus: str = "tab",
) -> dict[str, Any]:
    folder, fname, split = CORPUS_FILES[corpus]
    raw = {d["doc_id"]: d for d in _raw(folder, fname)}
    ids = [d.doc_id.removeprefix("tab-") for d in corpora.load(corpus, split).docs]
    docs = [raw[i] for i in ids]
    arr, types = {}, {}
    for name, preds in systems.items():
        if len(preds) != len(docs):
            raise ValueError(f"{name}: {len(preds)} predictions for {len(docs)} documents")
        rows, tt = [], defaultdict(lambda: [0.0, 0.0])
        for d, p in zip(docs, preds, strict=True):
            c, bt = doc_counts(d, p)
            rows.append([c[k] for k in _KEYS])
            for t, (g, h) in bt.items():
                tt[t][0] += g
                tt[t][1] += h
        arr[name] = np.array(rows)
        types[name] = {t: h / g for t, (g, h) in sorted(tt.items()) if g}
    w = weight_matrix("document", ids, resamples, seed)
    boot = {n: metrics(w @ a) for n, a in arr.items()}
    out: dict[str, Any] = {
        "protocol": PROTOCOL,
        "corpus": corpus,
        "n_docs": len(docs),
        "annotator_pairs": int(sum(len(d["annotations"]) for d in docs)),
        "resamples": resamples,
        "seed": seed,
        "point": {n: {k: float(v) for k, v in metrics(a.sum(0)).items()} for n, a in arr.items()},
        "ci95": {
            n: {
                k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
                for k, v in b.items()
            }
            for n, b in boot.items()
        },
        "char_recall_by_type": types,
        "counts": {n: dict(zip(_KEYS, map(float, a.sum(0)), strict=True)) for n, a in arr.items()},
        "paired_diff_p2.5_p50_p97.5": {},
    }
    names = list(systems)
    for a in names:
        for b in names:
            if a >= b:
                continue
            out["paired_diff_p2.5_p50_p97.5"][f"{a} - {b}"] = {
                k: [float(x) for x in np.percentile(boot[a][k] - boot[b][k], [2.5, 50, 97.5])]
                for k in boot[a]
            }
    out["planned"] = {
        f"{a} - {b}": {
            k: [float(x) for x in np.percentile(boot[a][k] - boot[b][k], [2.5, 50, 97.5])]
            for k in PLANNED_METRICS
        }
        for a, b in PLANNED
        if a in boot and b in boot
    }
    return out


def _raw(folder: str, fname: str) -> list[dict[str, Any]]:
    path = corpora.EXTERNAL / folder / fname
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", default="tab", choices=sorted(CORPUS_FILES))
    ap.add_argument("--system", action="append", required=True, metavar="NAME=CHECKPOINT")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    systems, commits = {}, {}
    for spec in args.system:
        name, path = spec.split("=", 1)
        systems[name], commits[name] = load_checkpoint(Path(path))
    res = score(systems, args.resamples, args.seed, args.corpus)
    res["commits"] = commits
    args.json.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    for n, m in res["point"].items():
        print(
            f"{n:22s} P {m['char_precision']:.3f} R {m['char_recall']:.3f} F1 {m['char_f1']:.3f}"
            f" ERdi {m['er_direct']:.3f} ERqi {m['er_quasi']:.3f}"
            f" direct-protected {m['direct_protected']:.3f}"
        )


if __name__ == "__main__":
    main()
