"""How often does chunking itself leak? Naive and overlapping chunking versus SafeStream.

Each corpus's test documents are concatenated, two newlines apart, into one stream
(logs arrive as streams). One detection pipeline then runs four ways:

* ``whole``: one pass over the stream, the reference ``Pi(T)``;
* ``naive``: fixed chunks of ``c`` characters, each detected on its own;
* ``overlap``: windows of ``c + o`` characters advancing by ``c``, each keeping the
  detections that start in its own ``c`` characters (common practice; no left
  context and no retreat), with ``o`` = 256 or the longest declared span;
* ``safestream``: ``engine.stream_windows`` with the pipeline's overlap, the
  smallest allowed emit size and random chunkings (chunk lengths uniform in
  ``1..2c``).

Reported against ``whole``: reference detections not fully covered (missed),
characters redacted that ``whole`` does not redact (extra), whether the detection
set is identical, and gold spans that ``whole`` fully redacts but the variant does
not (leaks caused by chunking alone). No text is written; counts only.

    python -m benchmarks.chunking_leak --corpus redactionbench --json out.json
"""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from benchmarks import corpora

Span = tuple[int, int, str]
SEP = "\n\n"


def concatenate(docs: list[corpora.Doc]) -> tuple[str, list[tuple[int, int]]]:
    """(stream, gold spans in stream offsets)."""
    parts, gold, off = [], [], 0
    for d in docs:
        parts.append(d.text)
        gold += [(off + g.start, off + g.end) for g in d.spans]
        off += len(d.text) + len(SEP)
    return SEP.join(parts), gold


def _spans(dets: Any, shift: int = 0) -> list[Span]:
    return [(d.start + shift, d.end + shift, d.entity_type.value) for d in dets]


def naive(text: str, detect: Callable[[str], Any], c: int) -> list[Span]:
    return [s for k in range(0, len(text), c) for s in _spans(detect(text[k : k + c]), k)]


def overlapping(text: str, detect: Callable[[str], Any], c: int, o: int) -> list[Span]:
    out = []
    for k in range(0, len(text), c):
        out += [s for s in _spans(detect(text[k : k + c + o]), k) if s[0] < k + c]
    return out


def _random_chunks(text: str, c: int, rng: random.Random) -> Iterator[str]:
    k = 0
    while k < len(text):
        n = rng.randint(1, 2 * c)
        yield text[k : k + n]
        k += n


def streamed(text: str, redactor: Any, c: int, seed: int) -> list[Span]:
    from safestream_redactor.engine import stream_windows

    out, off = [], 0
    chunks = _random_chunks(text, c, random.Random(seed))
    for segment, dets in stream_windows(
        chunks, redactor.detect, redactor.overlap, min_emit=redactor.overlap
    ):
        out += _spans(dets, off)
        off += len(segment)
    assert off == len(text)
    return out


def _mask(spans: list[Span], n: int) -> bytearray:
    m = bytearray(n)
    for s, e, _t in spans:
        m[max(0, s) : min(n, e)] = b"\x01" * (min(n, e) - max(0, s))
    return m


def compare(
    ref: list[Span], var: list[Span], gold: list[tuple[int, int]], n: int
) -> dict[str, Any]:
    rm, vm = _mask(ref, n), _mask(var, n)
    missed = [s for s in ref if not all(vm[s[0] : s[1]])]
    gold_leaks = [g for g in gold if all(rm[g[0] : g[1]]) and not all(vm[g[0] : g[1]])]
    return {
        "identical": sorted(ref) == sorted(var),
        "ref_detections": len(ref),
        "missed_detections": len(missed),
        "missed_chars": sum(1 for a, b in zip(rm, vm, strict=True) if a and not b),
        "extra_chars": sum(1 for a, b in zip(rm, vm, strict=True) if b and not a),
        "gold_spans": len(gold),
        "gold_spans_leaked_by_chunking": len(gold_leaks),
        "gold_chars_leaked_by_chunking": sum(e - s for s, e in gold_leaks),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--spacy", action="store_true", help="add the spaCy tier")
    ap.add_argument("--chunks", type=int, nargs="+", default=[1024, 4096, 16384, 65536])
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()

    import safestream_redactor
    from safestream_redactor.redactor import Redactor

    redactor = Redactor(backend="python", use_ner=args.spacy)
    corpus = corpora.load(args.corpus, args.split)
    text, gold = concatenate(corpus.docs)
    n = len(text)
    ref = _spans(redactor.detect(text))
    longest = max((d.requirements.max_span for d in redactor._detectors), default=8192)
    out: dict[str, Any] = {
        "corpus": args.corpus,
        "split": args.split,
        "pipeline": "pattern+spacy" if args.spacy else "pattern",
        "safestream_version": safestream_redactor.__version__,
        "stream_chars": n,
        "n_docs": len(corpus.docs),
        "overlap_w": redactor.overlap,
        "longest_declared_span": longest,
        "results": {},
    }
    for c in args.chunks:
        res: dict[str, Any] = {
            "naive": compare(ref, naive(text, redactor.detect, c), gold, n),
            "overlap_256": compare(ref, overlapping(text, redactor.detect, c, 256), gold, n),
            f"overlap_{longest}": compare(
                ref, overlapping(text, redactor.detect, c, longest), gold, n
            ),
        }
        runs = [compare(ref, streamed(text, redactor, c, s), gold, n) for s in range(args.seeds)]
        res["safestream"] = {
            "chunkings": len(runs),
            "all_identical": all(r["identical"] for r in runs),
            "max_missed_detections": max(r["missed_detections"] for r in runs),
            "max_gold_spans_leaked_by_chunking": max(
                r["gold_spans_leaked_by_chunking"] for r in runs
            ),
        }
        out["results"][str(c)] = res
        print(
            f"{args.corpus} c={c}:",
            "  ".join(
                f"{k} missed {v['missed_detections']}"
                f" gold-leaked {v['gold_spans_leaked_by_chunking']}"
                for k, v in res.items()
                if k != "safestream"
            ),
            f"  safestream identical {res['safestream']['all_identical']}",
            flush=True,
        )
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
