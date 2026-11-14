"""Does the overlap condition carry over to someone else's detectors? Presidio, chunked.

Presidio's pattern recognisers (no NLP engine) are wrapped as one detection
pipeline: their spans are merged into disjoint regions, as a redactor would mask
them. That pipeline then runs over each test corpus, concatenated into one stream,
four ways, exactly as in ``benchmarks/chunking_leak.py``: whole document, naive
chunks, overlapping windows, and SafeStream's streaming engine
(``engine.stream_windows``) with an overlap ``w`` and random chunkings.

The engine needs declared bounds. Presidio declares none, so we take them from its
recognisers: the longest span is capped at ``MAX_SPAN`` (spans longer than that are
reported and would void the condition), and regex lookarounds read only a few
characters on each side, covered by ``CONTEXT``. ``w = MAX_SPAN + CONTEXT`` then
satisfies Eq. (1). Whether the wrapped Presidio output equals its whole-document
output is measured, not assumed.

Run with Presidio's environment and the repository on the path:

    PYTHONPATH=src:. /path/to/presidio-venv/bin/python -m benchmarks.wrap_presidio \\
        --corpus presidio_research --json out.json
"""

from __future__ import annotations

import argparse
import json
import logging
import random
from pathlib import Path
from typing import Any

from benchmarks import corpora
from benchmarks.chunking_leak import (
    _random_chunks,
    _spans,
    compare,
    concatenate,
    naive,
    overlapping,
)

from safestream_redactor.engine import stream_windows
from safestream_redactor.entities import Detection, EntityType

MAX_SPAN = 2048
CONTEXT = 64
W = MAX_SPAN + CONTEXT


def _unbounded(regex: str) -> bool:
    """A lookahead that can scan to the end of the text (Presidio compiles with DOTALL)."""
    return "(?=.*" in regex or "(?=.+" in regex


def presidio_pipeline(bounded_only: bool = False) -> Any:
    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
    from presidio_analyzer import RecognizerRegistry

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"])
    ml = ("Spacy", "Stanza", "Transformers", "GLiNER")
    recognizers = [r for r in registry.recognizers if not type(r).__name__.startswith(ml)]
    dropped: list[str] = []
    if bounded_only:
        for rec in recognizers:
            patterns = getattr(rec, "patterns", None)
            if patterns:
                keep = [p for p in patterns if not _unbounded(p.regex)]
                dropped += [
                    f"{type(rec).__name__}:{p.name}" for p in patterns if _unbounded(p.regex)
                ]
                rec.patterns = keep
        recognizers = [r for r in recognizers if getattr(r, "patterns", True)]
    too_long: list[int] = []

    def detect(text: str) -> list[Detection]:
        spans = sorted(
            (r.start, r.end)
            for rec in recognizers
            for r in rec.analyze(text, rec.supported_entities, nlp_artifacts=None) or []
        )
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        for s, e in merged:
            if e - s > MAX_SPAN:
                too_long.append(e - s)
        return [
            Detection(s, e, text[s:e], EntityType.CUSTOM, 1.0, source="presidio") for s, e in merged
        ]

    detect.too_long = too_long  # type: ignore[attr-defined]
    detect.dropped = dropped  # type: ignore[attr-defined]
    return detect


def wrapped(text: str, detect: Any, c: int, seed: int) -> list[tuple[int, int, str]]:
    out, off = [], 0
    for segment, dets in stream_windows(
        _random_chunks(text, c, random.Random(seed)), detect, W, min_emit=W
    ):
        out += _spans(dets, off)
        off += len(segment)
    assert off == len(text)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--chunks", type=int, nargs="+", default=[1024, 4096])
    ap.add_argument("--seeds", type=int, default=2)
    ap.add_argument("--json", type=Path, required=True)
    ap.add_argument(
        "--bounded-only",
        action="store_true",
        help="drop patterns whose lookahead can scan to the end of the text",
    )
    args = ap.parse_args()

    docs = corpora.load(args.corpus, args.split).docs
    text, gold = concatenate(docs)
    detect = presidio_pipeline(args.bounded_only)
    ref = _spans(detect(text))
    res: dict[str, Any] = {
        "corpus": args.corpus,
        "split": args.split,
        "pipeline": "Presidio pattern recognisers, spans merged",
        "stream_chars": len(text),
        "declared": {"max_span": MAX_SPAN, "context": CONTEXT, "overlap_w": W},
        "bounded_only": args.bounded_only,
        "dropped_patterns": detect.dropped,
        "rows": [],
    }
    for c in args.chunks:
        row: dict[str, Any] = {"chunk": c}
        row["naive"] = compare(ref, naive(text, detect, c), gold, len(text))
        for o in (256, W):
            row[f"overlap_{o}"] = compare(ref, overlapping(text, detect, c, o), gold, len(text))
        runs = [
            compare(ref, wrapped(text, detect, c, s), gold, len(text)) for s in range(args.seeds)
        ]
        row["safestream_engine"] = {
            "identical": sum(r["identical"] for r in runs),
            "runs": len(runs),
            "missed": [r["missed_detections"] for r in runs],
        }
        res["rows"].append(row)
        print(
            f"{args.corpus} c={c}: naive missed {row['naive']['missed_detections']} "
            f"gold-leaked {row['naive']['gold_spans_leaked_by_chunking']}  "
            f"overlap_256 missed {row['overlap_256']['missed_detections']}  "
            f"overlap_{W} missed {row[f'overlap_{W}']['missed_detections']}  "
            f"engine identical {row['safestream_engine']['identical']} of {len(runs)}"
        )
    res["spans_longer_than_declared"] = len(detect.too_long)
    args.json.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
