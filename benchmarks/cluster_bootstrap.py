"""Document-level, cluster and two-stage (hierarchical) paired bootstrap.

The harness resamples documents i.i.d. That ignores two kinds of dependence:
secrets positives cluster by Nosey Parker rule (several examples per rule) and
RedactionBench documents cluster by domain (eleven categories); presidio-research
documents are generated from shared templates. This script joins
harness checkpoints (per-document predictions) on the same documents and scores
every system on three resampling schemes, each a single resample matrix shared by
all systems, so every difference is paired:

* ``document``: documents i.i.d. (reproduces the harness exactly, same seed);
* ``cluster``: whole clusters drawn with replacement, every document of a drawn
  cluster kept (the classical cluster bootstrap);
* ``two_stage``: clusters drawn with replacement, then documents drawn with
  replacement inside each drawn cluster (hierarchical bootstrap).

Clusters: ``realworld`` -- the document's ``source``; ``secrets`` -- the rule id
for a positive, the generator template for a gold-free document;
``redactionbench`` -- the document's domain;
``presidio_research`` -- the generator template; any other corpus -- the document
itself (all three schemes then coincide with ``document``).

    python -m benchmarks.cluster_bootstrap --corpus secrets --split test \\
        --system pattern=CKPT/secrets_test_safestream-python.json \\
        --system gitleaks=CKPT/secrets_test_gitleaks.json \\
        --pair pattern:gitleaks --json out.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
from benchmarks import corpora, harness

KEYS = (
    "char_p",
    "char_r",
    "char_f1",
    "entity_recall_covered",
    "fp_doc_rate",
    "mandatory_recall",
    "no_leak_doc_rate",
)
SCHEMES = ("document", "cluster", "two_stage")


def clusters_for(corpus: str, docs: list[corpora.Doc]) -> list[str]:
    """One cluster label per document."""
    if corpus == "secrets":
        out = []
        for d in docs:
            if d.doc_id.startswith("np-pos-"):
                out.append("rule:" + re.sub(r"-\d+$", "", d.doc_id[len("np-pos-") :]))
            else:  # neg-<template>-NNN
                out.append("neg:" + d.doc_id.split("-")[1])
        return out
    if corpus == "redactionbench":
        from benchmarks.redactionbench import loader

        res = loader.load_from_directory(
            corpora.ROOT / "benchmarks" / "data" / "redactionbench", loader.FieldSpec()
        )
        domain = {r.doc_id: r.domain for r in res.records}
        return ["domain:" + str(domain[d.doc_id]) for d in docs]
    if corpus == "presidio_research":  # documents generated from one template
        path = corpora.EXTERNAL / "presidio_research" / "synth_dataset_v2.json"
        rows = json.loads(path.read_text(encoding="utf-8"))
        return [f"template:{rows[int(d.doc_id[3:])]['template_id']}" for d in docs]
    if corpus == "loghub_ssh":  # sshd lines generated from one log template
        return ["template:" + d.doc_id.rsplit("-", 1)[1] for d in docs]
    if corpus == "realworld":  # documents from one source system or repository
        from benchmarks.realworld.data import sources_of

        return sources_of([d.doc_id for d in docs])
    return [d.doc_id for d in docs]


def weight_matrix(scheme: str, labels: list[str], resamples: int, seed: int = 0) -> np.ndarray:
    """resamples x n_docs matrix of multiplicities, one row per bootstrap draw."""
    n = len(labels)
    rng = np.random.default_rng(seed)
    if scheme == "document":  # identical draws to harness.evaluate
        return np.stack([np.bincount(rng.integers(0, n, n), minlength=n) for _ in range(resamples)])
    names = sorted(set(labels))
    members = [np.array([i for i, lab in enumerate(labels) if lab == c]) for c in names]
    w = np.zeros((resamples, n))
    for r in range(resamples):
        for c in rng.integers(0, len(names), len(names)):
            idx = members[c]
            if scheme == "cluster":
                w[r, idx] += 1
            else:  # two_stage
                np.add.at(w[r], idx[rng.integers(0, len(idx), len(idx))], 1)
    return w


def bootstrap(
    docs: list[corpora.Doc],
    labels: list[str],
    preds: dict[str, list[list[harness.Pred]]],
    pairs: list[tuple[str, str]],
    resamples: int = 2000,
    seed: int = 0,
) -> dict[str, Any]:
    """Point estimates, intervals and paired differences under every scheme."""
    mats = {
        name: [harness.score_doc(d, p) for d, p in zip(docs, ps, strict=True)]
        for name, ps in preds.items()
    }
    keys = sorted({k for cs in mats.values() for c in cs for k in c})
    col = {k: i for i, k in enumerate(keys)}
    arr = {n: np.array([[c.get(k, 0) for k in keys] for c in cs], float) for n, cs in mats.items()}

    def get(s: np.ndarray):
        return lambda key: s[..., col[key]] if key in col else np.zeros(s.shape[:-1])

    out: dict[str, Any] = {
        "point": {
            n: {k: float(v) for k, v in harness.metrics(get(a.sum(0))).items() if k in KEYS}
            for n, a in arr.items()
        },
        "ci95": {},
        "paired_diff_p2.5_p50_p97.5": {},
    }
    for scheme in SCHEMES:
        w = weight_matrix(scheme, labels, resamples, seed)
        boot = {n: harness.metrics(get(w @ a)) for n, a in arr.items()}
        out["ci95"][scheme] = {
            n: {
                k: [float(np.percentile(b[k], 2.5)), float(np.percentile(b[k], 97.5))] for k in KEYS
            }
            for n, b in boot.items()
        }
        out["paired_diff_p2.5_p50_p97.5"][scheme] = {
            f"{a} - {b}": {
                k: [float(np.percentile(boot[a][k] - boot[b][k], q)) for q in (2.5, 50, 97.5)]
                for k in KEYS
            }
            for a, b in pairs
        }
    return out


def load_checkpoint(path: Path) -> tuple[list[list[harness.Pred]], str]:
    """(per-document predictions, commit) from a harness checkpoint file."""
    saved = json.loads(Path(path).read_text(encoding="utf-8"))
    return [[tuple(p) for p in doc] for doc in saved["run"]["preds"]], saved["commit"]


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--system", action="append", required=True, metavar="NAME=CHECKPOINT")
    ap.add_argument("--pair", action="append", default=[], metavar="A:B")
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()

    docs = corpora.load(args.corpus, args.split).docs
    labels = clusters_for(args.corpus, docs)
    preds, commits = {}, {}
    for spec in args.system:
        name, path = spec.split("=", 1)
        preds[name], commits[name] = load_checkpoint(Path(path))
    res = bootstrap(
        docs, labels, preds, [tuple(p.split(":", 1)) for p in args.pair], args.resamples, args.seed
    )
    out: dict[str, Any] = {
        "corpus": args.corpus,
        "split": args.split,
        "resamples": args.resamples,
        "seed": args.seed,
        "n_docs": len(docs),
        "n_clusters": len(set(labels)),
        "cluster_sizes": {c: labels.count(c) for c in sorted(set(labels))},
        "harness_commit_per_system": commits,
        **res,
    }
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    for scheme in SCHEMES:
        print(f"## {scheme}")
        for pair, v in out["paired_diff_p2.5_p50_p97.5"][scheme].items():
            print(
                f"{pair:40}",
                "  ".join(
                    f"{k} {m:+.3f} [{lo:+.3f},{hi:+.3f}]"
                    for k, (lo, m, hi) in v.items()
                    if k
                    in ("char_f1", "entity_recall_covered", "mandatory_recall", "no_leak_doc_rate")
                ),
            )


if __name__ == "__main__":
    main()
