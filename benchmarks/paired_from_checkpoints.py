"""Paired bootstrap across harness checkpoints produced by different code versions.

Each harness run pairs only the systems it ran together. This joins checkpoints
from separate runs (e.g. pre-exposure SafeStream and Presidio) on the same
documents and computes their paired differences on one shared resample matrix.

    python -m benchmarks.paired_from_checkpoints --corpus redactionbench --split test \
        --system pre-pattern=PRE_CKPT_DIR/redactionbench_test_safestream-python.json \
        --system presidio-lg=PRESIDIO_CKPT_DIR/redactionbench_test_presidio-lg.json \
        --json out.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks import corpora, harness

KEYS = ("char_f1", "mandatory_recall", "no_leak_doc_rate")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--system", action="append", required=True, metavar="NAME=CHECKPOINT")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    docs = corpora.load(args.corpus, args.split).docs
    preds, commits = {}, {}
    for spec in args.system:
        name, path = spec.split("=", 1)
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
        preds[name] = [[tuple(p) for p in doc] for doc in saved["run"]["preds"]]
        commits[name] = saved["commit"]
    res = harness.evaluate(docs, preds, resamples=args.resamples, seed=0)
    out = {
        "corpus": args.corpus,
        "split": args.split,
        "resamples": args.resamples,
        "seed": 0,
        "harness_commit_per_system": commits,
        "point": {n: {k: res["systems"][n]["point"][k] for k in KEYS} for n in preds},
        "ci95": {n: {k: res["systems"][n]["ci95"][k] for k in KEYS} for n in preds},
        "paired_diff_p2.5_p50_p97.5": {
            pair: {k: v[k] for k in KEYS} for pair, v in res["paired_diff_ci95"].items()
        },
    }
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    for pair, v in out["paired_diff_p2.5_p50_p97.5"].items():
        print(
            f"{pair:34}",
            "  ".join(f"{k} {m:+.3f} [{lo:+.3f}, {hi:+.3f}]" for k, (lo, m, hi) in v.items()),
        )


if __name__ == "__main__":
    main()
