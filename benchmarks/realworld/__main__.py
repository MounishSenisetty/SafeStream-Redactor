"""Real-world evaluation pipeline. Run ``python -m benchmarks.realworld <command> -h``.

    validate             check the corpus layout, offsets, types and provenance
    import-labelstudio   convert a Label Studio JSON export into the layout
    agreement            inter-annotator agreement with bootstrap intervals
    score                score harness checkpoints: metrics, per-type, leaks, LaTeX

Freeze the corpus with ``python -m benchmarks.corpora.split realworld`` and run the
systems with ``python -m benchmarks.harness --corpus realworld --split test``
between ``agreement`` and ``score``; README.md gives the full sequence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from benchmarks import corpora
from benchmarks.cluster_bootstrap import load_checkpoint
from benchmarks.realworld import agreement, data, labelstudio, score

RESULTS = corpora.ROOT / "research" / "results" / "raw"


def _default_out(stem: str) -> Path:
    return RESULTS / f"{dt.date.today().isoformat()}_realworld_{stem}.json"


def cmd_validate(args: argparse.Namespace) -> int:
    ds = data.load_dataset(args.dir)
    print(json.dumps(data.summary(ds), indent=1))
    return 1 if ds.issues else 0


def cmd_import(args: argparse.Namespace) -> int:
    export = json.loads(Path(args.export).read_text(encoding="utf-8"))
    label_map = json.loads(Path(args.label_map).read_text()) if args.label_map else None
    counts = labelstudio.convert(export, args.dir or data.data_dir(), label_map)
    print(f"wrote {counts['documents']} documents, {counts['annotators']} annotator files")
    print("next: add provenance.json, then run `python -m benchmarks.realworld validate`")
    return 0


def cmd_agreement(args: argparse.Namespace) -> int:
    ds = data.load_dataset(args.dir)
    if ds.issues:
        print("fix validation issues first:\n  " + "\n  ".join(ds.issues), file=sys.stderr)
        return 1
    labels = data.sources_of([d.doc_id for d in ds.documents], ds.directory)
    res = agreement.agreement(ds, labels, args.resamples, args.seed)
    out = args.json or _default_out("agreement")
    out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    for pair, v in res["pairs"].items():
        ci = v["ci95"]["two_stage"]
        print(
            pair,
            "  ".join(
                f"{k} {v['point'][k]:.3f} [{ci[k][0]:.3f}, {ci[k][1]:.3f}]" for k in v["point"]
            ),
        )
    print(f"# wrote {out}", file=sys.stderr)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    ds = data.load_dataset(args.dir)
    corpus = corpora.load("realworld", "test")  # enforces the frozen manifest
    if [d.doc_id for d in corpus.docs] != [d.doc_id for d in ds.documents]:
        print("the frozen manifest does not cover every document in order", file=sys.stderr)
        return 1
    preds, commits = {}, {}
    for spec in args.system:
        name, path = spec.split("=", 1)
        preds[name], commits[name] = load_checkpoint(Path(path))
        if len(preds[name]) != len(ds.documents):
            print(f"{name}: {len(preds[name])} documents, corpus has {len(ds.documents)}")
            return 1
    labels = data.sources_of([d.doc_id for d in ds.documents], ds.directory)
    pairs = [tuple(p.split(":", 1)) for p in args.pair]
    cred = frozenset(args.credential_types.split(","))
    res = score.score(ds, preds, pairs, labels, cred, args.resamples, args.seed)  # type: ignore[arg-type]
    res |= {
        "harness_commit_per_system": commits,
        "provenance": {k: ds.provenance.get(k) for k in ("description", "collected")},
    }
    out = args.json or _default_out("scores")
    out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    names = dict(n.split("=", 1) for n in args.name) or {k: k for k in preds}
    if args.latex_dir:
        args.latex_dir.mkdir(parents=True, exist_ok=True)
        (args.latex_dir / "tab_realworld_main.tex").write_text(score.latex_main(res, names))
        (args.latex_dir / "tab_realworld_types.tex").write_text(score.latex_types(res, names))
        if pairs:
            (args.latex_dir / "tab_realworld_pairs.tex").write_text(score.latex_pairs(res, names))
    for name in preds:
        p = res["point"][name]
        print(
            f"{name:22}",
            "  ".join(f"{k} {p[k]:.3f}" for k in ("char_f1", "entity_recall_covered")),
            f"credential leaks {res['leaks'][name]['_credential_leaks']}",
        )
    print(f"# wrote {out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--dir", type=Path, help="corpus directory (default: $SAFESTREAM_REALWORLD_DIR)"
    )
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="check layout, offsets, types and provenance")
    imp = sub.add_parser("import-labelstudio", help="convert a Label Studio JSON export")
    imp.add_argument("export")
    imp.add_argument("--label-map", help="JSON object: Label Studio label -> TYPE[:subtype]")
    for name in ("agreement", "score"):
        p = sub.add_parser(name)
        p.add_argument("--json", type=Path)
        p.add_argument("--resamples", type=int, default=2000)
        p.add_argument("--seed", type=int, default=0)
    sc = sub.choices["score"]
    sc.add_argument("--system", action="append", required=True, metavar="NAME=CHECKPOINT")
    sc.add_argument("--pair", action="append", default=[], metavar="A:B")
    sc.add_argument("--name", action="append", default=[], metavar="NAME=LABEL")
    sc.add_argument("--credential-types", default="SECRET")
    sc.add_argument("--latex-dir", type=Path)
    args = ap.parse_args(argv)
    if args.dir:  # the harness and the corpus loader read the same location
        os.environ["SAFESTREAM_REALWORLD_DIR"] = str(args.dir)
    handler = {
        "validate": cmd_validate,
        "import-labelstudio": cmd_import,
        "agreement": cmd_agreement,
        "score": cmd_score,
    }[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
