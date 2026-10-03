"""Write the fixed dev/test split manifest for a corpus (run once, then commit).

    python -m benchmarks.corpora.split redactionbench presidio_research ai4privacy ...

Documents are shuffled with a fixed seed and halved: dev for tuning, test touched
only at the end of a phase. The manifest holds document ids and the SHA-256 of the
source, never text. An existing manifest is never overwritten (``--force`` exists
only to re-create one deliberately; re-splitting after looking at test results is
exactly the leak this file prevents).
"""

from __future__ import annotations

import argparse
import json
import random
import sys

from benchmarks import corpora

SEED = 20261003
# Corpora whose test half was seen during tuning before the split existed.
PREVIOUSLY_EXPOSED = {
    "redactionbench": "all 200 documents were used for error analysis and rule tuning "
    "before 2026-10-03; its test half is reported as 'previously exposed', not held out",
}


def _group(corpus: str, doc_id: str) -> str:
    """Documents that must land on the same side of the split.

    Nosey Parker repeats near-identical examples within one rule, so the secrets
    corpus splits by rule (a rule's positives and negatives together), never by
    example: dev and test then hold different vendor formats.
    """
    if corpus == "secrets":
        return doc_id.removeprefix("np-pos-").removeprefix("np-neg-").rsplit("-", 1)[0]
    return doc_id


def make_manifest(corpus: corpora.Corpus, seed: int = SEED) -> dict[str, object]:
    groups: dict[str, list[str]] = {}
    for d in corpus.docs:
        groups.setdefault(_group(corpus.name, d.doc_id), []).append(d.doc_id)
    order = sorted(groups)
    random.Random(seed).shuffle(order)
    dev: list[str] = []
    test: list[str] = []
    for key in order:  # fill dev to half the documents, whole groups at a time
        (dev if len(dev) < len(corpus.docs) // 2 else test).extend(groups[key])
    return {
        "corpus": corpus.name,
        "seed": seed,
        "source_revision": corpus.revision,
        "source_sha256": corpora.source_sha256(corpus),
        "n_docs": len(corpus.docs),
        "group_by": "rule" if corpus.name == "secrets" else "document",
        "previously_exposed": PREVIOUSLY_EXPOSED.get(corpus.name),
        "notes": corpus.notes,
        "dev": sorted(dev),
        "test": sorted(test),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("corpora", nargs="+", choices=sorted(corpora.LOADERS))
    ap.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    args = ap.parse_args()
    corpora.SPLITS.mkdir(exist_ok=True)
    for name in args.corpora:
        path = corpora.SPLITS / f"{name}.json"
        if path.exists() and not args.force:
            print(f"{name}: manifest exists, left untouched", file=sys.stderr)
            continue
        manifest = make_manifest(corpora.load(name))
        path.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
        print(f"{name}: {manifest['n_docs']} docs -> {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
