"""Head-to-head: SafeStream-Redactor vs Microsoft Presidio on labeled data.

Each tool runs in its own subprocess, so the numbers are per tool and not
cross-contaminated: model/pattern load time, analysis throughput (excluding the
load), and the process's peak RSS (its memory ceiling). The parent scores every
tool's spans against the same gold labels with the same code:

* entity recall — a gold span counts as caught only when *every* character of it
  is redacted (a half-masked SSN still leaks digits);
* character precision / recall — over the union of gold characters, so a tool is
  not penalised for drawing a span boundary one character differently.

Memory: "peak RSS" is the whole process; "tool RSS" subtracts what the process
held right after loading the dataset (for RedactionBench that includes pyarrow),
leaving the tool's own models, automata and working set.

Datasets
--------
``logs``            the adversarial synthetic corpus (``generate_hard_dataset.py``):
                    noisy log/JSON/CSV/SQL lines dense with hard negatives; gold =
                    email, phone, credit card, SSN, IPv4. Both tools are restricted
                    to those five types (Presidio: EMAIL_ADDRESS, PHONE_NUMBER,
                    CREDIT_CARD, US_SSN, IP_ADDRESS), so this measures format
                    coverage and false-positive resistance on structured PII.
``redactionbench``  the 200-document RedactionBench test split (real text; names,
                    addresses, keys, IDs, ...). Every tool runs its full default
                    configuration and is scored type-agnostically: what share of the
                    sensitive characters it redacts, and how much else it redacts.

Tools are grouped into **like-for-like tiers**; compare within a tier, never across:

*Pattern tier (no ML model on either side)*
    ``safestream-python`` / ``safestream-native`` (deterministic + entropy + contextual
    tiers) against ``presidio-regex`` (Presidio's own ``PatternRecognizer`` /
    checksum recognizers run directly, with **no** NLP engine, so spaCy is not
    in the timing or the memory).
*NER tier (a spaCy ``en_core_web_sm`` model on both sides)*
    ``safestream-native-ner`` against ``presidio-sm`` (the full ``AnalyzerEngine``
    on the same ``en_core_web_sm`` model).
*Reference*
    ``presidio`` (``AnalyzerEngine()`` defaults: every recognizer, spaCy
    ``en_core_web_lg``) -- Presidio as most users run it; its cost is dominated by
    the larger model, not the recognizers.

    python benchmarks/generate_hard_dataset.py --size-mb 1
    python benchmarks/presidio_compare.py --out benchmarks/PRESIDIO_COMPARISON.md

Needs ``presidio-analyzer`` + ``en_core_web_lg`` for the Presidio rows and
``pyarrow`` to read RedactionBench; a tool or dataset that is unavailable is
reported as skipped, never silently dropped.
"""

from __future__ import annotations

import argparse
import json
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TOOLS = (
    "safestream-native",
    "safestream-native-ner",
    # + the opt-in date/time tier: Presidio's default redacts DATE_TIME, so this is
    # the configuration that matches Presidio's scope on RedactionBench
    "safestream-native-ner-dates",
    "safestream-python",
    "presidio-regex",
    "presidio-sm",
    "presidio",
)
DATASETS = ("logs", "redactionbench")
LOG_TYPES = ["email", "phone", "credit_card", "ssn", "ipv4"]
PRESIDIO_LOG_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IP_ADDRESS"]
# Presidio runs spaCy over the text; spaCy refuses texts over 1M characters and
# its memory grows with length, so long texts are fed in line-aligned pieces.
PRESIDIO_PIECE = 20_000


# --- data ---------------------------------------------------------------------


def load_dataset(name: str) -> list[tuple[str, list[tuple[int, int]]]]:
    """[(text, [(gold_start, gold_end), ...]), ...]"""
    if name == "logs":
        data = ROOT / "benchmarks" / "data_hard"
        text = (data / "dataset.txt").read_text(encoding="utf-8")
        gold = json.loads((data / "dataset.json").read_text())
        gold = gold["entities"] if isinstance(gold, dict) else gold
        return [(text, [(g["start"], g["end"]) for g in gold])]
    sys.path.insert(0, str(ROOT))
    from benchmarks.redactionbench import loader

    res = loader.load_from_directory(ROOT / "benchmarks/data/redactionbench", loader.FieldSpec())
    return [(r.text, [(s.start, s.end) for s in r.spans]) for r in res.records]


def _pieces(text: str, size: int) -> list[tuple[int, str]]:
    out, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            nl = text.rfind("\n", start, end)
            end = nl + 1 if nl > start else end
        out.append((start, text[start:end]))
        start = end
    return out


# --- one tool, in a subprocess -----------------------------------------------


def _rss_mb() -> float:
    with open("/proc/self/statm") as f:
        return int(f.read().split()[1]) * resource.getpagesize() / 2**20


def _presidio_regex_analyzer(entities: list[str] | None):
    """Presidio's rule-based recognizers only, run directly with no NLP engine.

    This is the regex-vs-regex baseline: every non-ML recognizer in Presidio's
    default registry (patterns, checksums, the ``phonenumbers`` library) is called
    as ``recognizer.analyze(text, entities, nlp_artifacts=None)``, so neither spaCy
    nor its tokenizer is loaded or timed. Context-word score boosting (which needs
    NLP artifacts) is therefore absent -- it only re-ranks scores, and no score
    threshold is applied, so the *set* of spans is unchanged.
    """
    from presidio_analyzer import RecognizerRegistry

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(languages=["en"])
    ml = ("Spacy", "Stanza", "Transformers", "GLiNER")
    recognizers = [
        r
        for r in registry.recognizers
        if not type(r).__name__.startswith(ml)
        and (entities is None or set(entities) & set(r.supported_entities))
    ]

    def analyze(text: str) -> list[tuple[int, int]]:
        spans = []
        for rec in recognizers:
            wanted = [e for e in rec.supported_entities if entities is None or e in entities]
            spans.extend((r.start, r.end) for r in rec.analyze(text, wanted, nlp_artifacts=None))
        return spans

    return analyze


def run_one(tool: str, dataset: str) -> dict[str, Any]:
    docs = load_dataset(dataset)
    rss_data = _rss_mb()  # the dataset (and pyarrow, for RedactionBench) alone
    restricted = dataset == "logs"
    t0 = time.perf_counter()
    if tool.startswith("safestream"):
        from safestream_redactor import Redactor

        redactor = Redactor(
            backend="python" if tool == "safestream-python" else "native",
            use_ner="-ner" in tool,
            use_dates=tool.endswith("-dates"),
            types=LOG_TYPES if restricted else None,
        )

        def analyze(text: str) -> list[tuple[int, int]]:
            # the streaming engine, as files and pipes are processed in practice
            spans, offset = [], 0
            chunks = (text[i : i + redactor.chunk_size] for i in range(0, len(text), 65536))
            for segment, detections in redactor.detect_stream(chunks):
                spans.extend((offset + d.start, offset + d.end) for d in detections)
                offset += len(segment)
            return spans

    else:
        import logging

        logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
        entities = PRESIDIO_LOG_ENTITIES if restricted else None
        if tool == "presidio-regex":
            analyze = _presidio_regex_analyzer(entities)
        else:
            from presidio_analyzer import AnalyzerEngine

            if tool == "presidio-sm":
                from presidio_analyzer.nlp_engine import NlpEngineProvider

                nlp = NlpEngineProvider(
                    nlp_configuration={
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                    }
                ).create_engine()
                engine = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
            else:
                engine = AnalyzerEngine()

            def analyze(text: str) -> list[tuple[int, int]]:
                spans = []
                for offset, piece in _pieces(text, PRESIDIO_PIECE):
                    for r in engine.analyze(text=piece, language="en", entities=entities):
                        spans.append((offset + r.start, offset + r.end))
                return spans

        analyze("warm up the pipeline")
    load_s = time.perf_counter() - t0
    t1 = time.perf_counter()
    predictions = [analyze(text) for text, _gold in docs]
    analyze_s = time.perf_counter() - t1
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "tool": tool,
        "dataset": dataset,
        "load_s": load_s,
        "analyze_s": analyze_s,
        "bytes": sum(len(t.encode("utf-8")) for t, _ in docs),
        "peak_rss_mb": ru.ru_maxrss / 1024,
        "tool_rss_mb": ru.ru_maxrss / 1024 - rss_data,
        "predictions": predictions,
    }


# --- scoring ------------------------------------------------------------------


def score(docs: list, predictions: list[list[tuple[int, int]]]) -> dict[str, float]:
    tp_chars = gold_chars = pred_chars = 0
    caught = total = 0
    for (text, gold), pred in zip(docs, predictions, strict=True):
        g = bytearray(len(text))
        p = bytearray(len(text))
        for s, e in gold:
            g[s:e] = b"\x01" * (e - s)
        for s, e in pred:
            p[max(0, s) : max(0, e)] = b"\x01" * (max(0, e) - max(0, s))
        both = bytes(a & b for a, b in zip(g, p, strict=True))
        tp_chars += both.count(1)
        gold_chars += g.count(1)
        pred_chars += p.count(1)
        for s, e in gold:
            total += 1
            caught += all(p[s:e])
    return {
        "entity_recall": caught / total if total else 0.0,
        "char_precision": tp_chars / pred_chars if pred_chars else 0.0,
        "char_recall": tp_chars / gold_chars if gold_chars else 0.0,
        "gold_entities": total,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--run-one", nargs=2, metavar=("TOOL", "DATASET"), help=argparse.SUPPRESS)
    ap.add_argument("--tools", nargs="+", default=list(TOOLS), choices=TOOLS)
    ap.add_argument("--datasets", nargs="+", default=list(DATASETS), choices=DATASETS)
    ap.add_argument("--out", type=Path, help="write a markdown report here")
    ap.add_argument("--json", type=Path, help="write raw results (no spans) here")
    args = ap.parse_args()
    if args.run_one:
        json.dump(run_one(*args.run_one), sys.stdout)
        return

    rows: list[dict[str, Any]] = []
    for dataset in args.datasets:
        try:
            docs = load_dataset(dataset)
        except (OSError, ImportError, ValueError) as exc:
            print(f"# {dataset}: skipped ({exc})", file=sys.stderr)
            continue
        for tool in args.tools:
            print(f"# {dataset}: {tool} ...", file=sys.stderr, flush=True)
            proc = subprocess.run(
                [sys.executable, __file__, "--run-one", tool, dataset],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                reason = (proc.stderr.strip().splitlines() or ["failed"])[-1]
                print(f"#   skipped: {reason}", file=sys.stderr)
                rows.append({"tool": tool, "dataset": dataset, "skipped": reason})
                continue
            result = json.loads(proc.stdout)
            predictions = result.pop("predictions")
            result.update(score(docs, predictions))
            result["mb_s"] = result["bytes"] / 1e6 / result["analyze_s"]
            rows.append(result)

    lines = [
        "| Dataset | Tool | Entity recall | Char precision | Char recall | Throughput | "
        "Load | Peak RSS | Tool RSS |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        if "skipped" in r:
            lines.append(f"| {r['dataset']} | {r['tool']} | skipped: {r['skipped']} ||||||| ")
            continue
        lines.append(
            f"| {r['dataset']} | {r['tool']} | {r['entity_recall']:.3f} | "
            f"{r['char_precision']:.3f} | {r['char_recall']:.3f} | {r['mb_s']:.2f} MB/s | "
            f"{r['load_s']:.1f} s | {r['peak_rss_mb']:.0f} MB | {r['tool_rss_mb']:.0f} MB |"
        )
    table = "\n".join(lines)
    print(table)
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
    if args.out:
        env = f"{platform.python_version()} on {platform.machine()}, {platform.system()}"
        args.out.write_text(
            "# SafeStream-Redactor vs Presidio\n\n"
            f"Generated by `benchmarks/presidio_compare.py` (Python {env}).\n\n{table}\n"
        )


if __name__ == "__main__":
    main()
