"""Render the harness's raw JSON as one summary table per corpus (markdown).

    python -m benchmarks.summarize research/results/raw/2026-10-03_*_dev.json

Numbers are copied from the JSON, never retyped: each cell is the point estimate
and its 95% bootstrap CI. Character metrics are type-agnostic; entity metrics are
type-agnostic partial match (>= 50% of the gold span, one-to-one).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CAVEATS = {
    "redactionbench": "**Previously exposed**: all 200 documents were used to tune rules "
    "before the split existed; not a held-out result.",
    "conll2003": "**Not independent for the ONNX tier**: its model "
    "(`dslim/distilbert-NER`) was trained on CoNLL-2003 train.",
}
METRICS = (
    ("char_p", "Char P"),
    ("char_r", "Char R"),
    ("char_f1", "Char F1"),
    ("ent_p_partial", "Entity P"),
    ("ent_r_partial", "Entity R"),
    ("ent_f1_partial", "Entity F1"),
    ("entity_recall_covered", "Fully redacted"),
)


def cell(point: float, ci: list[float] | None) -> str:
    return f"{point:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else f"{point:.3f}"


def table(report: dict) -> str:
    extra = []
    if report.get("has_necessity"):
        extra += [("mandatory_recall", "Mandatory R"), ("no_leak_doc_rate", "No-leak docs")]
    if report.get("has_negatives"):
        extra += [("fp_doc_rate", "FP doc rate")]
    cols = list(METRICS) + extra
    lines = [
        f"#### {report['corpus']} (dev, {report['n_docs']} documents)",
        "",
    ]
    if report["corpus"] in CAVEATS:
        lines += [CAVEATS[report["corpus"]], ""]
    lines += [
        "| System | Tier | " + " | ".join(name for _, name in cols) + " | MB/s (1 thread) |",
        "|---|---|" + "---|" * (len(cols) + 1),
    ]
    for name, run in report["runs"].items():
        if "skipped" in run:
            lines.append(f"| {name} | | not run: {run['skipped']} |")
            continue
        s = report["scores"]["systems"][name]
        cells = [cell(s["point"][k], s["ci95"].get(k)) for k, _ in cols]
        tier = report["systems"].get(name, "")
        lines.append(f"| {name} | {tier} | " + " | ".join(cells) + f" | {run['mb_s']:.3g} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    order = ["presidio_research", "ai4privacy", "secrets", "redactionbench", "conll2003"]
    reports = [json.loads(Path(p).read_text(encoding="utf-8")) for p in sys.argv[1:]]
    reports.sort(key=lambda r: order.index(r["corpus"]) if r["corpus"] in order else 99)
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    print("\n".join(table(r) for r in reports))


if __name__ == "__main__":
    main()
