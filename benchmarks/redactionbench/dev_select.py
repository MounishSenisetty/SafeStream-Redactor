"""Choose a configuration on RedactionBench dev only, then score it on test once.

    python -m benchmarks.redactionbench.dev_select --out result.json [--dates]

The grid and the selection rule are fixed before any test score is seen: the
configuration with the highest dev character F1 wins (ties: higher dev mandatory
recall, then the earlier grid entry). Only that one configuration touches test.
Point ``PYTHONPATH`` at another checkout's ``src`` to run its code.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks import corpora, harness  # noqa: E402

THRESHOLDS = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--dates", action="store_true", help="add use_dates to the grid")
    args = ap.parse_args()

    import safestream_redactor

    grid = [
        {"min_confidence": t, "use_ner": ner, "use_entropy": ent}
        | ({"use_dates": d} if args.dates else {})
        for t, ner, ent, d in itertools.product(
            THRESHOLDS, (False, True), (True, False), (False, True) if args.dates else (False,)
        )
    ]
    dev = corpora.load("redactionbench", "dev").docs
    rows = []
    for cfg in grid:
        analyze = harness._safestream({"backend": "python", **cfg})
        preds = [analyze(d.text) for d in dev]
        point = harness.evaluate(dev, {"c": preds}, resamples=0)["systems"]["c"]["point"]
        rows.append({"config": cfg, "dev": point})
        print(cfg, round(point["char_f1"], 4), round(point["mandatory_recall"], 4), flush=True)
    best = max(
        range(len(rows)),
        key=lambda i: (rows[i]["dev"]["char_f1"], rows[i]["dev"]["mandatory_recall"], -i),
    )
    chosen = rows[best]["config"]
    test = corpora.load("redactionbench", "test").docs
    analyze = harness._safestream({"backend": "python", **chosen})
    test_scores = harness.evaluate(
        test, {"chosen": [analyze(d.text) for d in test]}, resamples=2000
    )["systems"]["chosen"]
    args.out.write_text(
        json.dumps(
            {
                "code": safestream_redactor.__file__,
                "selection_rule": "max dev char_f1; ties: dev mandatory_recall, grid order",
                "grid": rows,
                "chosen": chosen,
                "test": test_scores,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print("chosen", chosen, "test char_f1", round(test_scores["point"]["char_f1"], 4))


if __name__ == "__main__":
    main()
