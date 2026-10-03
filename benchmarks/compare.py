"""Before/after table for one change, with the Phase 1 stop rule.

    python -m benchmarks.compare research/results/raw/phase1/t0 research/results/raw/phase1/t1

Each argument is a filename prefix; ``<prefix>_<corpus>_dev.json`` is read for every
headline corpus. For every SafeStream system the primary metrics (char F1 and the
fully-redacted entity rate, all-gold and Presidio-scope) are printed before ->
after with the after-CI. **Stop rule:** a metric that drops by more than the width
of its *before* 95% CI is flagged, and the exit code is 1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORPORA = ("presidio_research", "ai4privacy", "secrets", "redactionbench")
PRIMARY = (
    ("char_f1", "char F1"),
    ("entity_recall_covered", "fully redacted"),
    ("scope_char_f1", "char F1 (P-scope)"),
    ("scope_fully_redacted", "fully redacted (P-scope)"),
    ("fp_doc_rate", "FP doc rate"),
)
LOWER_IS_BETTER = {"fp_doc_rate"}


def load(prefix: str, corpus: str) -> dict | None:
    path = Path(f"{prefix}_{corpus}_dev.json")
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def main() -> int:
    before_prefix, after_prefix = sys.argv[1], sys.argv[2]
    flagged = []
    for corpus in CORPORA:
        before, after = load(before_prefix, corpus), load(after_prefix, corpus)
        if before is None or after is None:
            continue
        print(f"\n### {corpus}")
        print("| System | Metric | Before | After [95% CI] | Change |")
        print("|---|---|---|---|---|")
        for system, scores in after["scores"]["systems"].items():
            if not system.startswith("safestream") or system not in before["scores"]["systems"]:
                continue
            b = before["scores"]["systems"][system]
            for key, label in PRIMARY:
                if key.startswith("scope") and not after.get("has_scope"):
                    continue
                if key == "fp_doc_rate" and not after.get("has_negatives"):
                    continue
                old, new = b["point"][key], scores["point"][key]
                lo, hi = scores["ci95"].get(key, [new, new])
                blo, bhi = b["ci95"].get(key, [old, old])
                worse = (new - old) if key in LOWER_IS_BETTER else (old - new)
                flag = ""
                if worse > (bhi - blo):
                    flag = " **STOP: worse by more than the CI width**"
                    flagged.append((corpus, system, label))
                print(
                    f"| {system} | {label} | {old:.3f} | {new:.3f} [{lo:.3f}, {hi:.3f}] | "
                    f"{new - old:+.3f}{flag} |"
                )
    if flagged:
        print("\nSTOP RULE TRIGGERED:", flagged)
        return 1
    print("\nStop rule: no metric dropped by more than its CI width.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
