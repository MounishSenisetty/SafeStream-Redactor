"""Secret-scanner sensitivity analysis: default false-positive filters versus none.

Both scanners ship filters aimed at example- or placeholder-like strings, and the
secrets corpus is made of rule-author examples, so default configurations may be
penalised more than they would be on real data. This script reruns each scanner
with its filters disabled and writes harness-format checkpoints, which
``benchmarks.cluster_bootstrap`` then scores against the saved SafeStream runs.

Variants (scanner output is parsed by the unchanged harness adapter):

* ``gitleaks-default-config``: ``-c`` with the release's own ``config/gitleaks.toml``
  (a control: must reproduce the built-in default exactly);
* ``gitleaks-nofilters``: the same file with the global ``[allowlist]`` and every
  ``[[rules.allowlists]]`` table (which hold the stopwords) removed; rule regexes,
  keywords and entropy thresholds are unchanged;
* ``trufflehog-nofilters``: ``--results=verified,unverified,unknown,filtered_unverified``,
  i.e. the default results plus those TruffleHog's false-positive filter drops.
  Still ``--no-verification``: no example credential is sent to a live service.

    GITLEAKS=... TRUFFLEHOG=... python -m benchmarks.scanner_sensitivity \\
        --corpus secrets --split test --gitleaks-default CFG --gitleaks-nofilters CFG \\
        --out-dir CKPT_DIR
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from benchmarks import corpora, harness


def _commit() -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=harness.ROOT
    )
    return out.stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--gitleaks-default", type=Path, required=True, metavar="TOML")
    ap.add_argument("--gitleaks-nofilters", type=Path, required=True, metavar="TOML")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    texts = [d.text for d in corpora.load(args.corpus, args.split).docs]
    gl, th = harness.SCANNERS["gitleaks"], harness.SCANNERS["trufflehog"]
    variants = {
        "gitleaks-default-config": ("gitleaks", [*gl, "-c", str(args.gitleaks_default)]),
        "gitleaks-nofilters": ("gitleaks", [*gl, "-c", str(args.gitleaks_nofilters)]),
        "trufflehog-nofilters": (
            "trufflehog",
            [*th, "--results=verified,unverified,unknown,filtered_unverified"],
        ),
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    commit = _commit()
    for name, (kind, cmd) in variants.items():
        saved = harness.SCANNERS[kind]
        harness.SCANNERS[kind] = cmd  # the adapter parses by scanner kind
        try:
            preds, wall, unplaced = harness._scan_batch(kind, texts)
        finally:
            harness.SCANNERS[kind] = saved
        n = sum(len(p) for p in preds)
        print(f"{name:26} {n:5d} spans, {unplaced} unplaced, {wall:.1f}s")
        run = {"system": name, "command": cmd[1:], "unplaced_findings": unplaced, "preds": preds}
        target = args.out_dir / f"{args.corpus}_{args.split}_{name}.json"
        target.write_text(json.dumps({"commit": commit, "run": run}), encoding="utf-8")


if __name__ == "__main__":
    main()
