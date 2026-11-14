"""Numbers audit: does every number a paper prints come from its raw results?

    python paper/audit_numbers.py conference
    python paper/audit_numbers.py journal

Every numeric value in the paper's raw result files is indexed (JSON leaves, plus
numbers in JSONL and markdown tables). Each number printed in the paper's content
(``check_disjoint.numbers``) is then matched against the index at the precision it is
printed with, also as a percentage (x100) and as a unit change (x1000: MB to kB, s to
ms). A number is:

* **traced**: it matches a raw value and has at least 3 significant digits, or 2 with
  a decimal point;
* **weak**: it matches, but is too short for the match to mean much (a small integer);
* **listed**: it matches nothing, so it must be a parameter, a count derived by hand,
  or a citation; ``<paper>/numbers_allowlist.txt`` gives each such number its reason;
* **UNTRACED**: none of the above. The audit fails if any remains.

Raw files: the conference uses ``research/results/raw/conf/``; the journal uses every
other file under ``research/results/raw/``. Neither may use the other's.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_disjoint import PAPERS, SKIP_FILES, numbers  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "research" / "results" / "raw"


def raw_files(paper: str) -> list[Path]:
    conf = RAW / "conf"
    files = [p for p in RAW.rglob("*") if p.is_file() and p.suffix in (".json", ".jsonl", ".md")]
    if paper == "conference":
        return [p for p in files if conf in p.parents]
    return [p for p in files if conf not in p.parents]


def _leaves(obj: Any) -> Iterator[float]:
    if isinstance(obj, bool):
        return
    if isinstance(obj, int | float):
        yield float(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and re.fullmatch(r"\d+(\.\d+)?", k):
                yield float(k)
            yield from _leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _leaves(v)


def index(files: list[Path]) -> set[float]:
    values: set[float] = set()
    for p in files:
        text = p.read_text(encoding="utf-8", errors="replace")
        if p.suffix == ".json":
            try:
                values.update(_leaves(json.loads(text)))
                continue
            except ValueError:
                pass
        if p.suffix == ".jsonl":
            for line in text.splitlines():
                try:
                    values.update(_leaves(json.loads(line)))
                except ValueError:
                    pass
            continue
        values.update(float(m) for m in re.findall(r"-?\d+(?:\.\d+)?", text))
    return values


def _round(v: float, places: int) -> str:
    q = Decimal(1).scaleb(-places)
    return str(Decimal(repr(v)).quantize(q, rounding=ROUND_HALF_UP))


def matches(printed: str, values: set[float], by_places: dict[int, set[str]]) -> bool:
    places = len(printed.split(".")[1]) if "." in printed else 0
    target = printed.lstrip("+-")
    if target in by_places[places]:
        return True
    try:
        x = float(target)
    except ValueError:
        return False
    return x in values


def significant(printed: str) -> bool:
    digits = printed.replace(".", "").lstrip("0")
    return len(digits) >= 3 or ("." in printed and len(digits) >= 2)


def main() -> None:
    paper = sys.argv[1]
    allow_file = PAPERS[paper].parent / "numbers_allowlist.txt"
    allow: dict[str, str] = {}
    if allow_file.exists():
        for line in allow_file.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                num, _, why = line.partition(" ")
                allow[num] = why.strip()
    values = index(raw_files(paper))
    by_places: dict[int, set[str]] = {}
    for p in range(0, 4):
        forms: set[str] = set()
        for v in values:
            for scaled in (v, v * 100, v * 1000, abs(v), abs(v) * 100):
                forms.add(_round(scaled, p))
        by_places[p] = forms
    text = "\n".join(
        f.read_text(encoding="utf-8")
        for f in sorted(PAPERS[paper].glob("*.tex"))
        if f.name not in SKIP_FILES
    )
    counts = {"traced": 0, "weak": 0, "listed": 0, "UNTRACED": 0}
    untraced: list[str] = []
    for n in sorted(set(numbers(text)), key=lambda s: (len(s), s)):
        if matches(n, values, by_places):
            counts["traced" if significant(n) else "weak"] += 1
        elif n in allow:
            counts["listed"] += 1
        else:
            counts["UNTRACED"] += 1
            untraced.append(n)
    print(f"{paper}: {len(values):,} raw values indexed from {len(raw_files(paper))} files")
    print(f"distinct printed numbers: {sum(counts.values())}  " + "  ".join(
        f"{k} {v}" for k, v in counts.items()))
    if untraced:
        print("UNTRACED:", " ".join(untraced))
    sys.exit(1 if untraced else 0)


if __name__ == "__main__":
    main()
