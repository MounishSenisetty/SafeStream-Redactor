"""How good and how cheap is the neural tier's regex gate, and is its context honest?

Gate (no model needed), per corpus:

* **gate recall** per gold type: the share of gold spans lying entirely inside some
  candidate window (a span outside every window can never be found by the model);
* **pass rate**: the share of characters sent to the model, and windows per KiB;
* **window lengths**: the distribution of merged-window lengths. A window longer than
  the declared context lets a decision depend on text further away than declared.

Context (needs the model, ``--context``): every detection of the ONNX tier is
re-checked with only ``k`` characters kept on each side of it; a detection that
disappears or changes is a *flip*. ``--adversarial`` builds lines of chained
Titlecase candidates of increasing length and compares streamed with whole-document
output of the ONNX tier.

    python -m benchmarks.gate_audit --corpus wnut17 ai4privacy loghub --json out.json
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
from pathlib import Path
from typing import Any

from benchmarks import corpora

NER_TYPES = ("PERSON", "ORGANIZATION", "LOCATION")
DECLARED = 256


def miss_kind(text: str, start: int, end: int) -> str:
    """Why a gold person name lies outside every window (a coarse, fixed taxonomy)."""
    value = text[start:end]
    before = text[text.rfind("\n", 0, start) + 1 : start].rstrip()
    if value[:1].islower() or value.startswith("@"):
        return "lower_case_or_handle"
    if value.isupper():
        return "all_caps"
    if len(value.split()) == 1:
        at_start = before == "" or before[-1:] in ".!?:\"'"
        return "single_word_sentence_start" if at_start else "single_word_other"
    return "multi_word"


def gate(docs: list[corpora.Doc]) -> dict[str, Any]:
    from safestream_redactor.detectors.onnx_ner import _candidate_windows

    total = inside = 0
    lengths: list[int] = []
    hit: dict[str, list[int]] = {t: [0, 0] for t in NER_TYPES}
    misses: dict[str, int] = {}
    for d in docs:
        windows = [(o, o + len(p)) for o, p in _candidate_windows(d.text)]
        total += len(d.text)
        inside += sum(e - s for s, e in windows)
        lengths += [e - s for s, e in windows]
        for g in d.spans:
            if g.type in hit:
                hit[g.type][1] += 1
                covered = any(s <= g.start and g.end <= e for s, e in windows)
                hit[g.type][0] += covered
                if g.type == "PERSON" and not covered:
                    k = miss_kind(d.text, g.start, g.end)
                    misses[k] = misses.get(k, 0) + 1
    q = statistics.quantiles(lengths, n=100) if len(lengths) > 1 else [0] * 99
    return {
        "docs": len(docs),
        "chars": total,
        "pass_rate": inside / total if total else 0.0,
        "windows": len(lengths),
        "windows_per_kib": len(lengths) / (total / 1024) if total else 0.0,
        "window_len_p50": q[49],
        "window_len_p99": q[98],
        "window_len_max": max(lengths, default=0),
        "windows_over_declared": sum(n > DECLARED for n in lengths),
        "gate_recall": {t: (h / n if n else None) for t, (h, n) in hit.items()},
        "gold": {t: n for t, (_h, n) in hit.items()},
        "person_misses_by_kind": dict(sorted(misses.items())),
    }


def _onnx_redactor(batch: int = 1) -> Any:
    from safestream_redactor import Redactor

    model = corpora.ROOT / "models" / "ner"
    return Redactor(
        load_plugins=False,
        use_onnx=True,
        onnx_model=str(model / "model.int8.onnx"),
        onnx_vocab=str(model / "tokenizer.json"),
        onnx_labels=str(model / "labels.json"),
        onnx_batch_size=batch,
    )


def context(docs: list[corpora.Doc], ks: list[int], limit: int) -> dict[str, Any]:
    redactor = _onnx_redactor()
    onnx = next(d for d in redactor._detectors if d.name.startswith("onnx"))
    out: dict[str, Any] = {"detections": 0, "flips": {str(k): 0 for k in ks}}
    for d in docs[:limit]:
        for det in onnx.detect(d.text):
            out["detections"] += 1
            for k in ks:
                lo, hi = max(0, det.start - k), min(len(d.text), det.end + k)
                again = {
                    (x.start + lo, x.end + lo, x.entity_type) for x in onnx.detect(d.text[lo:hi])
                }
                if (det.start, det.end, det.entity_type) not in again:
                    out["flips"][str(k)] += 1
    out["flip_rate"] = {
        k: (v / out["detections"] if out["detections"] else 0.0) for k, v in out["flips"].items()
    }
    return out


def adversarial(lengths: list[int], seeds: int) -> dict[str, Any]:
    """Lines of chained Titlecase candidates ("Ann Lee, Bo Kim, ...") of growing length."""
    from benchmarks.chunking_leak import _spans, streamed

    from safestream_redactor.detectors.onnx_ner import _candidate_windows

    redactor = _onnx_redactor()
    names = ["Ann Lee", "Bo Kim", "Cy Ruiz", "Di Moss", "Ed Park", "Flo Hart", "Gus Wynn"]
    out: dict[str, Any] = {}
    for n in lengths:
        rng = random.Random(n)
        line = ""
        while len(line) < n:
            line += rng.choice(names) + ", "
        text = ("Minutes of the meeting.\n" + line + "and others attended.\n") * 3
        ref = sorted(_spans(redactor.detect(text)))
        windows = [len(p) for _o, p in _candidate_windows(text)]
        identical = [
            sorted(streamed(text, redactor, c, s)) == ref
            for c in (64, 256, 1024)
            for s in range(seeds)
        ]
        out[str(n)] = {
            "chars": len(text),
            "longest_window": max(windows, default=0),
            "ref_detections": len(ref),
            "chunkings": len(identical),
            "identical": sum(identical),
        }
        print(
            f"adversarial line {n}: window {out[str(n)]['longest_window']}, "
            f"identical {sum(identical)}/{len(identical)}",
            flush=True,
        )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", nargs="+", default=[])
    ap.add_argument("--split", default="test")
    ap.add_argument("--context", nargs="*", type=int, help="k values for the context test")
    ap.add_argument("--context-limit", type=int, default=200, help="documents per corpus")
    ap.add_argument("--adversarial", nargs="*", type=int, help="chained-line lengths")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    report: dict[str, Any] = {"declared_context": DECLARED, "gate": {}, "context": {}}
    for name in args.corpus:
        split = args.split if name not in ("loghub", "benign", "agent_traces") else "all"
        docs = corpora.load(name, split).docs
        report["gate"][name] = g = gate(docs)
        print(f"{name}: pass rate {g['pass_rate']:.3f}, gate recall {g['gate_recall']}", flush=True)
        if args.context and any(d.spans for d in docs):
            report["context"][name] = c = context(docs, args.context, args.context_limit)
            print(f"{name}: context flips {c['flips']} of {c['detections']}", flush=True)
    if args.adversarial:
        report["adversarial"] = adversarial(args.adversarial, args.seeds)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
