"""Firewall between the journal and the conference paper, and a guard on edits.

    python paper/check_disjoint.py                 # journal vs conference
    python paper/check_disjoint.py --same OLD NEW  # NEW reports exactly OLD's numbers

Default mode, two checks:

1. **Shared result numbers.** Every number in each paper's content is extracted:
   LaTeX comments, labels, references, citations, file names and URLs are removed
   first. A number is shared if both papers print it. Method constants (the 95%
   level, 2,000 resamples, seed 0, chunk and window sizes both papers describe, years)
   are allow-listed below, each with its reason. Any other shared value must be a
   coincidence: it must trace to the conference's own raw results
   (``research/results/raw/conf/``, which the journal never uses; see
   ``audit_numbers.py``), so the two papers report different measurements that
   happen to round to the same digits. A shared value that does not trace there
   fails: the conference would be repeating a journal result.
2. **Shared 8-grams.** Commands and comments are stripped, the text is lower-cased,
   and for each paper the share of its distinct 8-word sequences that also occur in
   the other is computed. Above 2% in either direction fails.

``--same``: the multiset of numbers in NEW must equal OLD's, so text can be moved,
regrouped or reworded without a number changing, appearing or disappearing.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# method constants and descriptions both papers may state; never results
ALLOWED = {
    "95": "confidence level",
    "2000": "bootstrap resamples",
    "0": "bootstrap seed",
    "1": "small counts in prose",
    "2": "small counts in prose",
    "3": "small counts in prose",
    "4": "small counts in prose",
    "5": "small counts in prose",
    "8": "small counts in prose",
    "16": "small counts in prose",
    "32": "the gate's context in characters (a constant of the code)",
    "64": "chunk size 64 KiB, a configuration both papers describe",
    "256": "declared context of the neural tier (a constant of the code)",
    "1024": "chunk size, a configuration",
    "4096": "chunk size, a configuration",
    "8192": "pipeline overlap w*, a constant of the code",
    "2.1.0": "SARIF version",
    "3.8": "spaCy version",
    "2003": "CoNLL-2003, a dataset name",
    "2014": "year in a citation or dataset name",
    "2017": "year in a citation or dataset name",
    "2022": "year in a citation or dataset name",
    "2023": "year in a citation or dataset name",
    "2024": "year in a citation or dataset name",
    "2025": "year in a citation or dataset name",
    "2026": "year in a citation or dataset name",
}
PAPERS = {"journal": ROOT / "journal" / "content", "conference": ROOT / "conference" / "content"}
SKIP_FILES = {"preamble.tex"}


def strip(tex: str) -> str:
    tex = re.sub(r"(?<!\\)%.*", "", tex)
    tex = re.sub(r"\\(label|ref|eqref|cite|citep|citet|url|input|includegraphics|graphicspath"
                 r"|ssCiteAgent|ssCiteJournal)(\[[^\]]*\])?\{[^}]*\}", " ", tex)
    tex = re.sub(r"https?://\S+", " ", tex)
    tex = re.sub(r"\b[\w./-]+\.(py|json|md|tex|pdf|onnx|jsonl|log|zip|sh)\b", " ", tex)
    tex = re.sub(r"\\texttt\{[^}]*\}", " ", tex)  # code identifiers, commits, paths
    return tex


def numbers(tex: str) -> list[str]:
    tex = strip(tex).replace("{,}", ",").replace("\\,", "")
    out = []
    for m in re.finditer(r"(?<![\w.])(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)*)(?![\w])", tex):
        out.append(m.group(1).replace(",", ""))
    return out


def words(tex: str) -> list[str]:
    tex = strip(tex)
    tex = re.sub(r"\\[a-zA-Z]+\*?", " ", tex)
    return re.findall(r"[a-z]+(?:'[a-z]+)?", tex.lower())


def grams(ws: list[str], n: int = 8) -> set[tuple[str, ...]]:
    return {tuple(ws[i : i + n]) for i in range(len(ws) - n + 1)}


def read(folder: Path) -> str:
    return "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted(folder.glob("*.tex"))
        if p.name not in SKIP_FILES
    )


def body(tex: str) -> str:
    """A whole manuscript's document body, without its author block."""
    tex = tex.split("\\begin{document}", 1)[-1]
    return "\n".join(
        line for line in tex.split("\n") if not line.startswith(("\\author", "\\affil"))
    )


def same(old: Path, new: Path) -> int:
    a = Counter(numbers(body(old.read_text(encoding="utf-8"))))
    b = Counter(numbers(read(new) if new.is_dir() else new.read_text(encoding="utf-8")))
    lost, gained = a - b, b - a
    print(f"numbers: {sum(a.values())} before, {sum(b.values())} after")
    print(f"lost:   {dict(lost) or 'none'}")
    print(f"gained: {dict(gained) or 'none'}")
    return 1 if lost or gained else 0


def disjoint() -> int:
    texts = {k: read(v) for k, v in PAPERS.items()}
    nums = {k: set(numbers(t)) for k, t in texts.items()}
    shared = sorted(nums["journal"] & nums["conference"], key=lambda x: (len(x), x))
    from audit_numbers import _round, index, matches, raw_files

    conf = index(raw_files("conference"))
    by_places = {
        p: {_round(s, p) for v in conf for s in (v, v * 100, v * 1000, abs(v), abs(v) * 100)}
        for p in range(4)
    }
    rest = [x for x in shared if x not in ALLOWED]
    coincidental = [x for x in rest if matches(x, conf, by_places)]
    bad = [x for x in rest if x not in coincidental]
    print(f"distinct numbers: journal {len(nums['journal'])}, conference {len(nums['conference'])}")
    print(f"shared, allow-listed constants: {[x for x in shared if x in ALLOWED]}")
    print(f"shared, coincidental (conference value traced to its own raw results): "
          f"{len(coincidental)}")
    print(f"shared, NOT traced to the conference's results: {bad or 'none'}")
    g = {k: grams(words(t)) for k, t in texts.items()}
    common = g["journal"] & g["conference"]
    rates = {k: len(common) / max(1, len(v)) for k, v in g.items()}
    for k, r in rates.items():
        print(f"8-grams of the {k} also in the other: {len(common)}/{len(g[k])} = {100 * r:.2f}%")
    return 1 if bad or max(rates.values()) > 0.02 else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--same", nargs=2, type=Path, metavar=("OLD", "NEW"))
    args = ap.parse_args()
    sys.exit(same(*args.same) if args.same else disjoint())


if __name__ == "__main__":
    main()
