"""Reproducible RedactionBench CLI for SafeStream-Redactor.

Subcommands
-----------
``inspect``  Print the raw schema of the staged dataset files (top-level keys,
             value types, sample rows) and how the loader resolves them into
             text/spans/labels, plus which categories map onto SafeStream types
             and which are unsupported. Run this first to pin ``--*-key`` flags
             and ``--label-map`` before scoring.

``run``      Load the dataset, run every document through the real SafeStream
             pipeline (streaming engine by default), score predictions against
             the ground truth, and write raw predictions + detailed results +
             a markdown report to ``--out-dir``.

Examples
--------
    # 1. inspect the staged export
    python -m benchmarks.redactionbench.run inspect --data-dir benchmarks/data/redactionbench

    # 2. score the shipped architecture (structured PII/credentials; no NER)
    python -m benchmarks.redactionbench.run run \\
        --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench

    # 3. same, with the optional spaCy NER tier for names/orgs/locations
    python -m benchmarks.redactionbench.run run --ner \\
        --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench-ner

Nothing here mutates the core: the harness only calls the public Redactor API.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from safestream_redactor import Redactor, __version__

from . import adapter, loader, metrics

DEFAULT_REPO_ID = "RedactionBench/RedactionBench"


def _parse_label_map(spec: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        src, _, dst = pair.partition("=")
        if not dst:
            raise SystemExit(f"--label-map expects SRC=safestream_type pairs, got {pair!r}")
        mapping[src.strip()] = dst.strip()
    return mapping


def _field_spec(args: argparse.Namespace) -> loader.FieldSpec:
    return loader.FieldSpec(
        text_key=args.text_key,
        spans_key=args.spans_key,
        start_key=args.start_key,
        end_key=args.end_key,
        type_key=args.type_key,
        id_key=args.id_key,
        domain_key=args.domain_key,
        redacted_text_key=args.redacted_text_key,
        necessity_key=args.necessity_key,
    )


def _load(args: argparse.Namespace) -> loader.LoadResult:
    spec = _field_spec(args)
    if args.download:
        return loader.download_from_hf(args.repo_id, args.revision, spec)
    return loader.load_from_directory(Path(args.data_dir), spec)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def cmd_inspect(args: argparse.Namespace) -> int:
    directory = Path(args.data_dir)
    if not directory.exists():
        raise SystemExit(f"data dir {directory} does not exist; stage the dataset there first")
    raw = loader.inspect_raw(directory, sample=args.samples)
    print(json.dumps(raw, indent=2, ensure_ascii=False, default=str))

    # Also show how the loader would resolve records and the label coverage.
    result = loader.load_from_directory(directory, _field_spec(args))
    label_map = adapter.build_label_map(_parse_label_map(args.label_map))
    gold_labels: Counter[str] = Counter()
    unsupported: Counter[str] = Counter()
    for rec in result.records:
        for span in rec.spans:
            gold_labels[span.label] += 1
            if adapter.map_gold_label(span.label, label_map) is None:
                unsupported[span.label] += 1
    print("\n=== loader resolution ===")
    print(json.dumps(result.resolved_fields, indent=2))
    print(f"parsed records: {len(result.records)} / {result.row_count} raw rows")
    if result.skipped:
        print(f"skipped rows (first {len(result.skipped)}): {json.dumps(result.skipped[:5])}")
    print(f"revision: {result.revision}")
    # Is this a necessity-labelled corpus (RedactionBench: mandatory/contextual)
    # or a PII-typed one? That decides how `run` scores it.
    distinct = {label.strip().lower() for label in gold_labels}
    necessity_mode = bool(distinct) and distinct <= set(metrics.NECESSITY_VOCAB)
    print("\n=== gold span-label counts ===")
    for label, n in gold_labels.most_common():
        if necessity_mode:
            note = "(necessity class — binary redaction scoring)"
        else:
            mapped = adapter.map_gold_label(label, label_map)
            note = f"-> {mapped}" if mapped else "-> UNSUPPORTED (SafeStream has no detector)"
        print(f"  {label:<28} {n:>7}  {note}")
    if necessity_mode:
        print(
            "\nDetected NECESSITY labels (mandatory/contextual): `run` will score this as "
            "binary redaction — character-level coverage (R-Score style) plus type-agnostic "
            "spans, split by necessity. The dataset has no per-PII-type gold, so per-type "
            "precision/recall is not computed; the predicted-type distribution is reported "
            "instead. Force with `--gold-label-kind necessity`."
        )
    elif unsupported:
        print(
            "\nNOTE: unsupported categories are reported but excluded from the "
            "type-aware precision/recall (SafeStream never claims to detect them). "
            "They ARE counted in the honest all-gold character-coverage recall."
        )
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _build_redactor(args: argparse.Namespace) -> Redactor:
    types = None
    if args.types:
        types = [t.strip() for t in args.types.split(",") if t.strip()]
    return Redactor(
        types=types,
        use_ner=args.ner,
        min_confidence=args.min_confidence,
        custom_words=tuple(w for w in args.custom_word or []),
    )


def cmd_run(args: argparse.Namespace) -> int:
    started = time.time()
    result = _load(args)
    if not result.records:
        raise SystemExit(
            "no records parsed. Run `inspect` and pin the schema with --text-key / "
            "--spans-key / --start-key / --end-key / --type-key."
        )
    records = result.records
    if args.limit:
        records = records[: args.limit]

    # Detect the gold-label kind. RedactionBench labels each span by *necessity*
    # (mandatory/contextual) rather than a PII type, so it is scored as binary
    # redaction (character coverage + type-agnostic spans). Other corpora label
    # PII types and take the per-type path. Auto-detect unless overridden.
    gold_labels = {span.label.strip().lower() for rec in records for span in rec.spans}
    kind = args.gold_label_kind
    if kind == "auto":
        kind = (
            "necessity"
            if gold_labels and gold_labels <= set(metrics.NECESSITY_VOCAB)
            else "pii_type"
        )
    if kind == "necessity":
        return _run_binary(args, result, records, started)

    label_map = adapter.build_label_map(_parse_label_map(args.label_map))

    # Determine the evaluated (supported) SafeStream types from mapped gold.
    eval_types: set[str] = set()
    unsupported_categories: Counter[str] = Counter()
    for rec in records:
        for span in rec.spans:
            mapped = adapter.map_gold_label(span.label, label_map)
            if mapped is None:
                unsupported_categories[span.label] += 1
            else:
                eval_types.add(mapped)

    redactor = _build_redactor(args)

    per_record_scores: list[metrics.RecordScore] = []
    per_domain: dict[str, list[metrics.RecordScore]] = defaultdict(list)
    predictions_dump: list[dict[str, Any]] = []
    failed_samples: list[dict[str, Any]] = []

    for rec in records:
        try:
            preds = adapter.predict(redactor, rec.text, args.mode, args.chunk_size)
        except Exception as exc:  # a document the pipeline could not process
            failed_samples.append({"doc_id": rec.doc_id, "error": f"{type(exc).__name__}: {exc}"})
            if args.raise_on_error:
                raise
            continue

        gold_supported: list[metrics.Triple] = []
        gold_all: list[metrics.Triple] = []
        for span in rec.spans:
            gold_all.append((span.start, span.end, span.label))
            mapped = adapter.map_gold_label(span.label, label_map)
            if mapped is not None:
                gold_supported.append((span.start, span.end, mapped))
        pred_triples: list[metrics.Triple] = [(p.start, p.end, p.label) for p in preds]

        score = metrics.score_record(
            rec.doc_id,
            len(rec.text),
            gold_supported,
            gold_all,
            pred_triples,
            eval_types,
            args.overlap_threshold,
        )
        per_record_scores.append(score)
        per_domain[rec.domain or "(none)"].append(score)

        predictions_dump.append(
            {
                "doc_id": rec.doc_id,
                "domain": rec.domain,
                "text_length": len(rec.text),
                "gold": [
                    {
                        "start": s.start,
                        "end": s.end,
                        "label": s.label,
                        "mapped": adapter.map_gold_label(s.label, label_map),
                        "necessity": s.necessity,
                    }
                    for s in rec.spans
                ],
                "predictions": [
                    {
                        "start": p.start,
                        "end": p.end,
                        "type": p.label,
                        "confidence": round(p.confidence, 4),
                        "source": p.source,
                    }
                    for p in preds
                ],
                "scores": {
                    "type_aware": {t: prf.as_dict() for t, prf in score.type_aware.items()},
                    "type_agnostic": score.type_agnostic.as_dict(),
                    "chars_supported": score.chars_supported.as_dict(),
                    "chars_all_gold": score.chars_all_gold.as_dict(),
                    "exact_document": score.exact_document,
                },
            }
        )

    agg = metrics.aggregate(per_record_scores, eval_types)
    duration = time.time() - started

    meta = _build_meta(
        args,
        result,
        records,
        eval_types,
        unsupported_categories,
        failed_samples,
        redactor,
        duration,
    )
    results_json = _build_results_json(meta, agg, per_domain, eval_types)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_predictions(out_dir / "predictions.jsonl", predictions_dump)
    (out_dir / "results.json").write_text(
        json.dumps(results_json, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_per_type_csv(out_dir / "per_type.csv", agg)
    report = _render_report(results_json)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    print(report)
    print(
        f"\nWrote: {out_dir / 'predictions.jsonl'}, {out_dir / 'results.json'}, "
        f"{out_dir / 'per_type.csv'}, {out_dir / 'report.md'}"
    )
    return 0


def _run_binary(
    args: argparse.Namespace,
    result: loader.LoadResult,
    records: list[loader.RBRecord],
    started: float,
) -> int:
    """Score a necessity-labelled corpus (RedactionBench) as binary redaction."""
    redactor = _build_redactor(args)
    scores: list[metrics.BinaryRecordScore] = []
    predictions_dump: list[dict[str, Any]] = []
    failed_samples: list[dict[str, Any]] = []
    pred_type_counts: Counter[str] = Counter()

    for rec in records:
        try:
            preds = adapter.predict(redactor, rec.text, args.mode, args.chunk_size)
        except Exception as exc:
            failed_samples.append({"doc_id": rec.doc_id, "error": f"{type(exc).__name__}: {exc}"})
            if args.raise_on_error:
                raise
            continue
        for p in preds:
            pred_type_counts[p.label] += 1
        gold: list[metrics.GoldSpan] = [
            (s.start, s.end, s.label.strip().lower()) for s in rec.spans
        ]
        pred_triples = [(p.start, p.end, p.label) for p in preds]
        sc = metrics.score_binary_record(
            rec.doc_id, rec.domain, len(rec.text), gold, pred_triples, args.overlap_threshold
        )
        scores.append(sc)
        predictions_dump.append(
            {
                "doc_id": rec.doc_id,
                "domain": rec.domain,
                "text_length": len(rec.text),
                "gold": [{"start": s.start, "end": s.end, "necessity": s.label} for s in rec.spans],
                "predictions": [
                    {
                        "start": p.start,
                        "end": p.end,
                        "type": p.label,
                        "confidence": round(p.confidence, 4),
                        "source": p.source,
                    }
                    for p in preds
                ],
                "scores": {
                    "char_all": sc.chars["all"].as_dict(),
                    "char_mandatory": sc.chars["mandatory"].as_dict(),
                    "char_contextual": sc.chars["contextual"].as_dict(),
                    "span_all": sc.spans["all"].as_dict(),
                    "mandatory_fully_covered": sc.mandatory_fully_covered,
                },
            }
        )

    agg = metrics.aggregate_binary(scores)
    duration = time.time() - started
    meta = _build_meta(args, result, records, set(), Counter(), failed_samples, redactor, duration)
    meta["task"] = (
        "binary redaction (necessity: mandatory/contextual) — RedactionBench R-Score style"
    )
    meta["config"]["gold_label_kind"] = "necessity"
    meta["predicted_type_distribution"] = dict(pred_type_counts.most_common())

    results_json = _build_binary_results(meta, agg)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_predictions(out_dir / "predictions.jsonl", predictions_dump)
    (out_dir / "results.json").write_text(
        json.dumps(results_json, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_binary_csv(out_dir / "per_domain.csv", agg)
    report = _render_binary_report(results_json)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    print(report)
    print(
        f"\nWrote: {out_dir / 'predictions.jsonl'}, {out_dir / 'results.json'}, "
        f"{out_dir / 'per_domain.csv'}, {out_dir / 'report.md'}"
    )
    return 0


def _build_binary_results(meta: dict[str, Any], agg: metrics.BinaryAggregate) -> dict[str, Any]:
    point, lo, hi = agg.char_f1_ci
    return {
        "metadata": meta,
        "overall": {
            "documents": agg.documents,
            "predicted_spans_total": agg.n_pred_total,
            "character_level_rscore_style": {
                "note": "per-character redaction mask; formatting-agnostic (R-Score methodology). "
                "Precision/F1/accuracy are meaningful for the 'all' subset; for the "
                "mandatory/contextual subsets read RECALL (coverage of that subset).",
                "all": agg.chars["all"].as_dict(),
                "mandatory": agg.chars["mandatory"].as_dict(),
                "contextual": agg.chars["contextual"].as_dict(),
                "char_f1_all_bootstrap_ci_95": [round(point, 4), round(lo, 4), round(hi, 4)],
            },
            "span_level_type_agnostic": {
                "note": ">=threshold overlap, greedy 1:1, any predicted type counts (dataset has "
                "no PII types). Recall = gold redaction spans covered; precision = predictions "
                "that land on a gold span.",
                "all": agg.spans["all"].as_dict(),
                "mandatory": agg.spans["mandatory"].as_dict(),
                "contextual": agg.spans["contextual"].as_dict(),
            },
            "mandatory_protection": {
                "note": "fraction of documents with EVERY mandatory character redacted (no leak) "
                "— a per-document DLP accuracy, distinct from precision/recall.",
                "no_leak_document_rate": round(agg.mandatory_no_leak_rate, 4),
            },
        },
        "per_domain": agg.per_domain,
    }


def _write_binary_csv(path: Path, agg: metrics.BinaryAggregate) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "domain",
                "documents",
                "char_precision",
                "char_recall",
                "char_f1",
                "char_mandatory_recall",
                "span_precision",
                "span_recall",
                "span_f1",
            ]
        )
        for domain, d in agg.per_domain.items():
            ca = d["char_all"]  # type: ignore[index]
            sa = d["span_all"]  # type: ignore[index]
            w.writerow(
                [
                    domain,
                    d["documents"],
                    ca["char_precision"],
                    ca["char_recall"],
                    ca["char_f1"],
                    d["char_mandatory_recall"],
                    sa["precision"],
                    sa["recall"],
                    sa["f1"],
                ]
            )
        # overall row
        ov_c = agg.chars["all"]
        ov_s = agg.spans["all"]
        w.writerow(
            [
                "OVERALL",
                agg.documents,
                f"{ov_c.precision:.4f}",
                f"{ov_c.recall:.4f}",
                f"{ov_c.f1:.4f}",
                f"{agg.chars['mandatory'].recall:.4f}",
                f"{ov_s.precision:.4f}",
                f"{ov_s.recall:.4f}",
                f"{ov_s.f1:.4f}",
            ]
        )


def _render_binary_report(r: dict[str, Any]) -> str:
    m = r["metadata"]
    o = r["overall"]
    cl = o["character_level_rscore_style"]
    sl = o["span_level_type_agnostic"]
    ci = cl["char_f1_all_bootstrap_ci_95"]
    L: list[str] = []
    L.append("# RedactionBench results — SafeStream-Redactor\n")
    L.append(f"- **Dataset**: `{m['dataset']['repo_id']}`  ·  source: {m['dataset']['source']}")
    L.append(f"- **Revision**: `{m['dataset']['revision']}`")
    L.append(f"- **Task**: {m['task']}")
    L.append(
        f"- **Documents scored**: {o['documents']}  "
        f"(parsed {m['dataset']['parsed_records']} of {m['dataset']['raw_rows']} raw rows)"
    )
    L.append(
        f"- **SafeStream version**: {m['safestream_version']}  ·  "
        f"mode: **{m['config']['prediction_mode']}**  ·  chunk={m['config']['chunk_size']}  ·  "
        f"min_confidence={m['config']['min_confidence']}  ·  NER={m['config']['use_ner']}"
    )
    L.append(f"- **Detector tiers**: {', '.join(m['config']['detector_tiers'])}")
    L.append(
        f"- **Span match**: ≥{m['config']['overlap_match_threshold']:.0%} overlap, "
        f"type-agnostic (dataset has no PII types)\n"
    )

    L.append(
        "> RedactionBench annotates each span by **necessity** (mandatory vs contextual), "
        "not by PII type, so this is a **binary redaction** evaluation — did the system hide "
        "the characters that must be hidden? The character-level metric follows the dataset's "
        "R-Score methodology (formatting-agnostic). Per-PII-type recall is **not computable** "
        "from this dataset; the predicted-type distribution is reported instead.\n"
    )

    ca, cm, cc = cl["all"], cl["mandatory"], cl["contextual"]
    L.append("## Character-level coverage (R-Score style)\n")
    L.append("| Subset | Precision | Recall | F1 | Accuracy | char TP | char FP | char FN |")
    L.append("|---|--:|--:|--:|--:|--:|--:|--:|")
    L.append(
        f"| all gold | {ca['char_precision']:.3f} | {ca['char_recall']:.3f} | "
        f"{ca['char_f1']:.3f} | {ca['char_accuracy']:.3f} | {ca['char_tp']} | "
        f"{ca['char_fp']} | {ca['char_fn']} |"
    )
    L.append(
        f"| mandatory (read recall) | — | **{cm['char_recall']:.3f}** | — | — | "
        f"{cm['char_tp']} | — | {cm['char_fn']} |"
    )
    L.append(
        f"| contextual (read recall) | — | {cc['char_recall']:.3f} | — | — | "
        f"{cc['char_tp']} | — | {cc['char_fn']} |"
    )
    L.append("")
    L.append(
        f"- **Character-F1 (all gold)**: {ca['char_f1']:.3f}  "
        f"(95% bootstrap CI [{ci[1]:.3f}, {ci[2]:.3f}])"
    )
    L.append(f"- **Mandatory character recall** (must-redact coverage): {cm['char_recall']:.3f}")
    L.append(f"- **Contextual character recall**: {cc['char_recall']:.3f}")
    L.append(
        f"- **No-mandatory-leak document rate**: "
        f"{o['mandatory_protection']['no_leak_document_rate']:.3f}  "
        f"(documents with every mandatory character redacted; per-document, not P/R/F1)\n"
    )

    sa, sm, sc = sl["all"], sl["mandatory"], sl["contextual"]
    L.append("## Span-level (type-agnostic, ≥overlap match)\n")
    L.append("| Subset | Precision | Recall | F1 | TP | FP | FN |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    L.append(
        f"| all gold | {sa['precision']:.3f} | {sa['recall']:.3f} | {sa['f1']:.3f} | "
        f"{sa['tp']} | {sa['fp']} | {sa['fn']} |"
    )
    L.append(
        f"| mandatory | {sm['precision']:.3f} | {sm['recall']:.3f} | {sm['f1']:.3f} | "
        f"{sm['tp']} | {sm['fp']} | {sm['fn']} |"
    )
    L.append(
        f"| contextual | {sc['precision']:.3f} | {sc['recall']:.3f} | {sc['f1']:.3f} | "
        f"{sc['tp']} | {sc['fp']} | {sc['fn']} |"
    )
    L.append(
        "\n_Span precision is low by construction: SafeStream emits one span per detected "
        "entity, while gold segments a value into many adjacent mandatory/contextual spans, "
        "so one prediction can only 1:1-match one of them. Character coverage above is the "
        "faithful measure._\n"
    )

    L.append("## Per domain\n")
    L.append("| Domain | Docs | Char P | Char R | Char F1 | Mandatory char recall | Span F1 |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    for domain, d in r["per_domain"].items():
        cad = d["char_all"]
        sad = d["span_all"]
        L.append(
            f"| {domain} | {d['documents']} | {cad['char_precision']:.3f} | "
            f"{cad['char_recall']:.3f} | {cad['char_f1']:.3f} | "
            f"{d['char_mandatory_recall']:.3f} | {sad['f1']:.3f} |"
        )
    L.append("")

    if m.get("predicted_type_distribution"):
        L.append("## What SafeStream predicted (by entity type)\n")
        L.append(
            "The dataset has no gold PII types, so this is the distribution of the "
            "**predictions'** types (not scored against gold types).\n"
        )
        L.append("| SafeStream type | predicted spans |")
        L.append("|---|--:|")
        for t, n in m["predicted_type_distribution"].items():
            L.append(f"| {t} | {n} |")
        L.append("")

    if m["failed_samples"]:
        L.append(f"## Failed samples ({len(m['failed_samples'])})\n")
        for fs in m["failed_samples"][:20]:
            L.append(f"- `{fs['doc_id']}`: {fs['error']}")
        L.append("")

    L.append("## Reproduce\n")
    L.append("```bash\n" + m["command"] + "\n```")
    L.append(
        f"\n_Environment_: Python {m['python']}, {m['platform']}, "
        f"run took {m['duration_seconds']}s."
    )
    return "\n".join(L)


def _build_meta(
    args: argparse.Namespace,
    result: loader.LoadResult,
    records: list[loader.RBRecord],
    eval_types: set[str],
    unsupported: Counter[str],
    failed: list[dict[str, Any]],
    redactor: Redactor,
    duration: float,
) -> dict[str, Any]:
    return {
        "tool": "safestream-redactor",
        "safestream_version": __version__,
        "dataset": {
            "repo_id": args.repo_id,
            "source": result.source,
            "revision": result.revision,
            "files": result.files,
            "raw_rows": result.row_count,
            "parsed_records": len(result.records),
            "scored_records": len(records),
            "resolved_fields": result.resolved_fields,
            "load_skipped": result.skipped[:10],
        },
        "config": {
            "prediction_mode": args.mode,
            "chunk_size": args.chunk_size,
            "overlap_match_threshold": args.overlap_threshold,
            "min_confidence": args.min_confidence,
            "use_ner": args.ner,
            "types": args.types,
            "detector_tiers": redactor.detector_names,
            "label_map_overrides": args.label_map,
        },
        "evaluated_types": sorted(eval_types),
        "unsupported_categories": dict(unsupported.most_common()),
        "failed_samples": failed,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "duration_seconds": round(duration, 3),
        "command": "python -m benchmarks.redactionbench.run " + " ".join(sys.argv[1:]),
    }


def _build_results_json(
    meta: dict[str, Any],
    agg: metrics.Aggregate,
    per_domain: dict[str, list[metrics.RecordScore]],
    eval_types: set[str],
) -> dict[str, Any]:
    point, lo, hi = agg.f1_ci
    domain_summary: dict[str, Any] = {}
    for domain, dscores in sorted(per_domain.items()):
        dagg = metrics.aggregate(dscores, eval_types)
        domain_summary[domain] = {
            "documents": dagg.documents,
            "span_micro": dagg.micro.as_dict(),
            "char_supported": dagg.chars_supported.as_dict(),
        }
    return {
        "metadata": meta,
        "overall": {
            "documents": agg.documents,
            "span_level": {
                "note": "type-aware, greedy 1:1, >=threshold gold-overlap match",
                "micro": agg.micro.as_dict(),
                "macro_f1": round(agg.macro_f1, 4),
                "micro_f1_bootstrap_ci_95": [round(point, 4), round(lo, 4), round(hi, 4)],
                "type_agnostic": agg.type_agnostic.as_dict(),
            },
            "character_level_rscore_style": {
                "note": "per-character redaction mask; formatting-agnostic (R-Score methodology)",
                "supported_scope": agg.chars_supported.as_dict(),
                "all_gold_scope": agg.chars_all_gold.as_dict(),
            },
            "dataset_level_accuracy": {
                "note": "fraction of documents whose predicted mask exactly equals the "
                "supported-scope gold mask (per-document, NOT precision/recall)",
                "exact_document_rate": round(agg.dataset_accuracy, 4),
            },
        },
        "per_type": {t: prf.as_dict() for t, prf in sorted(agg.per_type.items())},
        "per_domain": domain_summary,
    }


def _write_predictions(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_per_type_csv(path: Path, agg: metrics.Aggregate) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "tp", "fp", "fn", "precision", "recall", "f1"])
        for t, prf in sorted(agg.per_type.items()):
            w.writerow(
                [
                    t,
                    prf.tp,
                    prf.fp,
                    prf.fn,
                    f"{prf.precision:.4f}",
                    f"{prf.recall:.4f}",
                    f"{prf.f1:.4f}",
                ]
            )
        w.writerow(
            [
                "MICRO",
                agg.micro.tp,
                agg.micro.fp,
                agg.micro.fn,
                f"{agg.micro.precision:.4f}",
                f"{agg.micro.recall:.4f}",
                f"{agg.micro.f1:.4f}",
            ]
        )


def _render_report(r: dict[str, Any]) -> str:
    m = r["metadata"]
    o = r["overall"]
    sl = o["span_level"]
    cl = o["character_level_rscore_style"]
    L: list[str] = []
    L.append("# RedactionBench results — SafeStream-Redactor\n")
    L.append(f"- **Dataset**: `{m['dataset']['repo_id']}`  ·  source: {m['dataset']['source']}")
    L.append(f"- **Revision**: `{m['dataset']['revision']}`")
    L.append(
        f"- **Documents scored**: {o['documents']}  "
        f"(parsed {m['dataset']['parsed_records']} of {m['dataset']['raw_rows']} raw rows)"
    )
    L.append(
        f"- **SafeStream version**: {m['safestream_version']}  ·  "
        f"prediction mode: **{m['config']['prediction_mode']}**  ·  "
        f"chunk={m['config']['chunk_size']}  ·  min_confidence={m['config']['min_confidence']}  "
        f"·  NER={m['config']['use_ner']}"
    )
    L.append(f"- **Detector tiers**: {', '.join(m['config']['detector_tiers'])}")
    L.append(f"- **Evaluated types**: {', '.join(m['evaluated_types']) or '(none)'}")
    L.append(
        f"- **Span match**: ≥{m['config']['overlap_match_threshold']:.0%} gold overlap, "
        f"type-aware, greedy 1:1\n"
    )

    ci = sl["micro_f1_bootstrap_ci_95"]
    L.append("## Overall\n")
    L.append("| Metric | Precision | Recall | F1 | TP | FP | FN |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    mi = sl["micro"]
    L.append(
        f"| Span (micro, type-aware) | {mi['precision']:.3f} | {mi['recall']:.3f} | "
        f"{mi['f1']:.3f} | {mi['tp']} | {mi['fp']} | {mi['fn']} |"
    )
    ta = sl["type_agnostic"]
    L.append(
        f"| Span (type-agnostic, location only) | {ta['precision']:.3f} | {ta['recall']:.3f} | "
        f"{ta['f1']:.3f} | {ta['tp']} | {ta['fp']} | {ta['fn']} |"
    )
    cs = cl["supported_scope"]
    L.append(
        f"| Char coverage (supported scope) | {cs['char_precision']:.3f} | "
        f"{cs['char_recall']:.3f} | {cs['char_f1']:.3f} | {cs['char_tp']} | "
        f"{cs['char_fp']} | {cs['char_fn']} |"
    )
    ca = cl["all_gold_scope"]
    L.append(
        f"| Char coverage (ALL gold, honest) | {ca['char_precision']:.3f} | "
        f"{ca['char_recall']:.3f} | {ca['char_f1']:.3f} | {ca['char_tp']} | "
        f"{ca['char_fp']} | {ca['char_fn']} |"
    )
    L.append("")
    L.append(
        f"- **Span micro-F1**: {sl['micro']['f1']:.3f}  (95% bootstrap CI "
        f"[{ci[1]:.3f}, {ci[2]:.3f}])"
    )
    L.append(f"- **Span macro-F1** (mean over types): {sl['macro_f1']:.3f}")
    L.append(f"- **Character accuracy (supported scope)**: {cs['char_accuracy']:.3f}")
    L.append(
        f"- **Dataset-level accuracy** (documents redacted exactly right): "
        f"{o['dataset_level_accuracy']['exact_document_rate']:.3f}  "
        f"— a per-document rate, distinct from precision/recall/F1\n"
    )

    L.append("## Per entity type (span-level, type-aware)\n")
    L.append("| Type | Precision | Recall | F1 | TP | FP | FN |")
    L.append("|---|--:|--:|--:|--:|--:|--:|")
    for t, prf in sorted(r["per_type"].items()):
        L.append(
            f"| {t} | {prf['precision']:.3f} | {prf['recall']:.3f} | {prf['f1']:.3f} | "
            f"{prf['tp']} | {prf['fp']} | {prf['fn']} |"
        )
    L.append("")

    if r["per_domain"] and len(r["per_domain"]) > 1:
        L.append("## Per domain (span micro-F1)\n")
        L.append("| Domain | Docs | Precision | Recall | F1 |")
        L.append("|---|--:|--:|--:|--:|")
        for domain, d in sorted(r["per_domain"].items()):
            sm = d["span_micro"]
            L.append(
                f"| {domain} | {d['documents']} | {sm['precision']:.3f} | "
                f"{sm['recall']:.3f} | {sm['f1']:.3f} |"
            )
        L.append("")

    if m["unsupported_categories"]:
        L.append("## Unsupported gold categories\n")
        L.append(
            "These categories are annotated in the dataset but SafeStream ships no "
            "detector for them, so they are excluded from type-aware precision/recall "
            "(counting them as misses would penalise the tool for something it never "
            "claims to do). They ARE included in the *all-gold* character-coverage recall.\n"
        )
        L.append("| Category | Gold spans |")
        L.append("|---|--:|")
        for cat, n in m["unsupported_categories"].items():
            L.append(f"| {cat} | {n} |")
        L.append("")

    if m["failed_samples"]:
        L.append(f"## Failed samples ({len(m['failed_samples'])})\n")
        for fs in m["failed_samples"][:20]:
            L.append(f"- `{fs['doc_id']}`: {fs['error']}")
        L.append("")

    L.append("## Reproduce\n")
    L.append("```bash\n" + m["command"] + "\n```")
    L.append(
        f"\n_Environment_: Python {m['python']}, {m['platform']}, "
        f"run took {m['duration_seconds']}s."
    )
    return "\n".join(L)


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--data-dir",
        default="benchmarks/data/redactionbench",
        help="directory with staged dataset files (parquet/jsonl/json/csv)",
    )
    p.add_argument(
        "--download",
        action="store_true",
        help="download from Hugging Face instead of reading --data-dir "
        "(needs `datasets` and network access to huggingface.co)",
    )
    p.add_argument("--repo-id", default=DEFAULT_REPO_ID, help="HF dataset repo id")
    p.add_argument("--revision", default=None, help="HF dataset revision/commit to pin")
    p.add_argument(
        "--label-map",
        default="",
        help="comma-separated SRC=safestream_type overrides for category mapping",
    )
    # schema overrides (pin after `inspect`)
    p.add_argument("--text-key")
    p.add_argument("--spans-key")
    p.add_argument("--start-key")
    p.add_argument("--end-key")
    p.add_argument("--type-key")
    p.add_argument("--id-key")
    p.add_argument("--domain-key")
    p.add_argument("--redacted-text-key")
    p.add_argument("--necessity-key")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="benchmarks.redactionbench.run",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("inspect", help="print raw schema + loader resolution + label coverage")
    _add_common(pi)
    pi.add_argument("--samples", type=int, default=3, help="sample rows to print")
    pi.set_defaults(func=cmd_inspect)

    pr = sub.add_parser("run", help="run the pipeline and score against ground truth")
    _add_common(pr)
    pr.add_argument(
        "--out-dir",
        default="benchmarks/results/redactionbench",
        help="where to write predictions/results/report",
    )
    pr.add_argument(
        "--mode",
        choices=["streaming", "whole"],
        default="streaming",
        help="prediction path: streaming (constant-memory engine) or whole-document",
    )
    pr.add_argument(
        "--chunk-size",
        type=int,
        default=4096,
        help="streaming chunk size in chars (small values stress chunk boundaries)",
    )
    pr.add_argument(
        "--overlap-threshold",
        type=float,
        default=0.5,
        help="min fraction of a gold span a prediction must cover to count as a hit",
    )
    pr.add_argument(
        "--gold-label-kind",
        choices=["auto", "pii_type", "necessity"],
        default="auto",
        help="how to interpret gold span labels: PII types (per-type scoring) or necessity "
        "classes like mandatory/contextual (binary redaction scoring, RedactionBench). "
        "'auto' detects necessity vocabularies.",
    )
    pr.add_argument("--min-confidence", type=float, default=0.5)
    pr.add_argument("--ner", action="store_true", help="enable the optional spaCy NER tier")
    pr.add_argument(
        "--types", default=None, help="restrict SafeStream to these entity types (comma-separated)"
    )
    pr.add_argument("--custom-word", action="append", help="literal word to always redact")
    pr.add_argument("--limit", type=int, default=0, help="score only the first N documents")
    pr.add_argument(
        "--raise-on-error",
        action="store_true",
        help="re-raise on a document the pipeline cannot process (default: record it)",
    )
    pr.set_defaults(func=cmd_run)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
