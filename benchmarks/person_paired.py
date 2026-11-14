"""Person-name recall with paired bootstrap intervals, from harness checkpoints.

PERSON character recall (gold PERSON characters covered by any prediction) and
PERSON covered-entity recall (gold PERSON spans fully covered), per system, with
95% percentile intervals over documents and paired differences for the planned
comparisons. All systems share one resample matrix (2,000 resamples, seed 0),
exactly as ``benchmarks/harness.py`` does.

    python -m benchmarks.person_paired --corpus wnut17 --split test \\
        --ckpt research/results/raw/conf/ckpt_wnut17 --json out.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
from benchmarks import corpora

PAIRS = [
    ("safestream-native-onnx", "safestream-native"),  # P1
    ("safestream-native-onnx", "safestream-native-spacy"),  # P2
    ("safestream-native-onnx", "safestream-native-onnx-ungated"),  # P4, cost of the gate
    ("safestream-native-onnx", "presidio-lg"),
    ("safestream-native-onnx", "presidio-sm"),
]


def counters(doc: corpora.Doc, preds: list[list[Any]], etype: str) -> list[float]:
    covered = bytearray(len(doc.text))
    for s, e, _t in preds:
        covered[max(0, s) : min(len(doc.text), e)] = b"\x01" * (min(len(doc.text), e) - max(0, s))
    gold = [g for g in doc.spans if g.type == etype]
    chars = sum(g.end - g.start for g in gold)
    hit = sum(sum(covered[g.start : g.end]) for g in gold)
    full = sum(1 for g in gold if all(covered[g.start : g.end]))
    return [hit, chars, full, len(gold)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--ckpt", type=Path, required=True)
    ap.add_argument("--type", default="PERSON")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    docs = corpora.load(args.corpus, args.split).docs
    mats: dict[str, np.ndarray] = {}
    for f in sorted(args.ckpt.glob(f"{args.corpus}_{args.split}_*.json")):
        system = f.stem.removeprefix(f"{args.corpus}_{args.split}_")
        preds = json.loads(f.read_text(encoding="utf-8"))["run"]["preds"]
        mats[system] = np.array(
            [counters(d, p, args.type) for d, p in zip(docs, preds, strict=True)], dtype=float
        )
    rng = np.random.default_rng(0)
    n = len(docs)
    weights = np.stack(
        [np.bincount(rng.integers(0, n, n), minlength=n) for _ in range(args.resamples)]
    )

    def rates(m: np.ndarray, w: np.ndarray | None = None) -> np.ndarray:
        s = m.sum(0) if w is None else w @ m
        s = np.atleast_2d(s)
        return np.stack([s[:, 0] / s[:, 1], s[:, 2] / s[:, 3]], axis=-1)

    out: dict[str, Any] = {"corpus": args.corpus, "type": args.type, "n_docs": n, "systems": {}}
    boot = {}
    for name, m in mats.items():
        point = rates(m)[0]
        boot[name] = rates(m, weights)
        ci = np.percentile(boot[name], [2.5, 97.5], axis=0)
        out["systems"][name] = {
            "gold_spans": int(m[:, 3].sum()),
            "char_recall": float(point[0]),
            "char_recall_ci": [float(ci[0, 0]), float(ci[1, 0])],
            "covered_recall": float(point[1]),
            "covered_recall_ci": [float(ci[0, 1]), float(ci[1, 1])],
        }
    out["paired"] = {}
    for a, b in PAIRS:
        if a in boot and b in boot:
            d = boot[a] - boot[b]
            q = np.percentile(d, [2.5, 50, 97.5], axis=0)
            out["paired"][f"{a} - {b}"] = {
                "char_recall": [float(x) for x in q[:, 0]],
                "covered_recall": [float(x) for x in q[:, 1]],
            }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    for k, v in out["paired"].items():
        print(f"{args.corpus} {k}: char recall {v['char_recall']}")


if __name__ == "__main__":
    main()
