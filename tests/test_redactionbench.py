"""Tests for the RedactionBench evaluation harness (benchmarks/redactionbench).

These exercise the harness plumbing — schema-adaptive loading, absolute-offset
reconstruction from the streaming engine, span/character metrics, and the CLI —
on a tiny synthetic fixture. They do NOT require the real dataset or network and
make no accuracy claim; they only guarantee the harness measures correctly.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# The harness lives under benchmarks/ (not an installed package), so load it by path.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

pytest.importorskip("safestream_redactor")

if importlib.util.find_spec("benchmarks.redactionbench.loader") is None:  # pragma: no cover
    pytest.skip("redactionbench harness not importable", allow_module_level=True)

from benchmarks.redactionbench import adapter, loader, metrics  # noqa: E402
from benchmarks.redactionbench import run as rb_run  # noqa: E402

from safestream_redactor import Redactor  # noqa: E402


def _write_fixture(tmp_path: Path) -> Path:
    t1 = "Email bob@corp.io and SSN 123-45-6789 today."
    t2 = "Key AKIAIOSFODNN7EXAMPLE and name Jane Roe."
    rows = [
        {
            "id": "d1",
            "domain": "logs",
            "full_text": t1,
            "spans": [
                {
                    "start": t1.index("bob@corp.io"),
                    "end": t1.index("bob@corp.io") + 11,
                    "type": "EMAIL_ADDRESS",
                },
                {
                    "start": t1.index("123-45-6789"),
                    "end": t1.index("123-45-6789") + 11,
                    "type": "US_SSN",
                },
            ],
        },
        {
            "id": "d2",
            "domain": "devops",
            "full_text": t2,
            "spans": [
                {
                    "start": t2.index("AKIAIOSFODNN7EXAMPLE"),
                    "end": t2.index("AKIAIOSFODNN7EXAMPLE") + 20,
                    "type": "aws_key",
                },
                {
                    "start": t2.index("Jane Roe"),
                    "end": t2.index("Jane Roe") + 8,
                    "type": "PERSON",
                },  # needs NER; a recall miss without it
            ],
        },
    ]
    d = tmp_path / "rb"
    d.mkdir()
    with (d / "test.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return d


def test_loader_resolves_schema(tmp_path: Path) -> None:
    d = _write_fixture(tmp_path)
    res = loader.load_from_directory(d, loader.FieldSpec())
    assert len(res.records) == 2
    assert res.resolved_fields["text"] == "full_text"
    assert res.resolved_fields["spans"] == "spans"
    rec = res.records[0]
    assert rec.doc_id == "d1"
    assert rec.domain == "logs"
    assert len(rec.spans) == 2
    # spans stay within text bounds
    for s in rec.spans:
        assert 0 <= s.start <= s.end <= len(rec.text)


def test_streaming_matches_whole_document() -> None:
    r = Redactor()
    text = "Email bob@corp.io key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789 " * 40
    # tiny chunks force many chunk boundaries through the entities
    streaming = adapter.predict_streaming(r, text, chunk_size=16)
    whole = adapter.predict_whole(r, text)
    key = lambda ps: sorted((p.start, p.end, p.label) for p in ps)  # noqa: E731
    assert key(streaming) == key(whole)


def test_span_matching_partial_and_type_aware() -> None:
    # gold [10,20) email; a prediction covering 60% counts as a hit at 0.5
    gold = [(10, 20, "email")]
    preds = [(12, 20, "email")]  # covers 8/10 = 80%
    out = metrics.score_type_aware(gold, preds, {"email"}, threshold=0.5)
    assert out["email"] == metrics.PRF(1, 0, 0)
    # wrong type -> not a type-aware hit (but type-agnostic still hits by location)
    preds_wrong = [(12, 20, "phone")]
    out2 = metrics.score_type_aware(gold, preds_wrong, {"email"}, threshold=0.5)
    assert out2["email"] == metrics.PRF(0, 0, 1)
    ag = metrics.score_type_agnostic(gold, [(12, 20, "phone")], {"email"}, threshold=0.5)
    assert ag == metrics.PRF(1, 0, 0)


def test_char_coverage_formatting_agnostic() -> None:
    # gold and pred cover the same characters -> perfect char coverage
    length = 30
    cc = metrics.score_chars([(5, 15)], [(5, 15)], length)
    assert cc.tp == 10 and cc.fp == 0 and cc.fn == 0 and cc.tn == 20
    assert cc.f1 == 1.0 and cc.accuracy == 1.0
    # partial overlap
    cc2 = metrics.score_chars([(5, 15)], [(10, 20)], length)
    assert cc2.tp == 5 and cc2.fn == 5 and cc2.fp == 5


def test_end_to_end_cli_writes_outputs(tmp_path: Path) -> None:
    d = _write_fixture(tmp_path)
    out = tmp_path / "out"
    rc = rb_run.main(["run", "--data-dir", str(d), "--out-dir", str(out), "--chunk-size", "8"])
    assert rc == 0
    for name in ("predictions.jsonl", "results.json", "per_type.csv", "report.md"):
        assert (out / name).is_file(), name
    results = json.loads((out / "results.json").read_text())
    per_type = results["per_type"]
    # deterministic tiers must catch the email, ssn, and aws key regardless of chunking
    assert per_type["email"]["tp"] == 1
    assert per_type["ssn"]["tp"] == 1
    assert per_type["aws_key"]["tp"] == 1
    # person is a recall miss without NER
    assert per_type["person"]["fn"] == 1
    # metric families are reported and distinct
    overall = results["overall"]
    assert "span_level" in overall
    assert "character_level_rscore_style" in overall
    assert "dataset_level_accuracy" in overall
    assert 0.0 <= overall["dataset_level_accuracy"]["exact_document_rate"] <= 1.0


def test_unsupported_category_reported(tmp_path: Path) -> None:
    text = "The DNA sequence ACGT is here."
    d = tmp_path / "rb2"
    d.mkdir()
    (d / "test.jsonl").write_text(
        json.dumps(
            {
                "id": "x",
                "full_text": text,
                "spans": [{"start": 4, "end": 16, "type": "DNA_SEQUENCE"}],
            }
        )
        + "\n"
    )
    out = tmp_path / "out2"
    rb_run.main(["run", "--data-dir", str(d), "--out-dir", str(out)])
    results = json.loads((out / "results.json").read_text())
    assert "DNA_SEQUENCE" in results["metadata"]["unsupported_categories"]


# --- binary / necessity mode (RedactionBench's real structure) -------------


def _write_necessity_fixture(tmp_path: Path) -> Path:
    # raw_text + spans labelled mandatory/contextual (no PII types), like RedactionBench
    t = "Email bob@corp.io and key AKIAIOSFODNN7EXAMPLE here."
    m1 = t.index("bob@corp.io")
    m2 = t.index("AKIAIOSFODNN7EXAMPLE")
    rows = [
        {
            "raw_text": t,
            "category": "emails",
            "genre": "sample",
            "spans": [
                {"start": m1, "end": m1 + 11, "label": "mandatory"},
                {"start": m2, "end": m2 + 20, "label": "mandatory"},
                {"start": 0, "end": 5, "label": "contextual"},  # "Email" word
            ],
        }
    ]
    d = tmp_path / "rbn"
    d.mkdir()
    with (d / "test.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    # a metadata sidecar that must be ignored by the loader
    (d / "croissant.json").write_text(json.dumps({"@type": "Dataset", "name": "x"}))
    return d


def test_loader_skips_croissant_and_reads_raw_text(tmp_path: Path) -> None:
    d = _write_necessity_fixture(tmp_path)
    res = loader.load_from_directory(d, loader.FieldSpec())
    assert len(res.records) == 1  # croissant.json ignored
    assert res.resolved_fields["text"] == "raw_text"
    assert {s.label for s in res.records[0].spans} == {"mandatory", "contextual"}


def test_score_spans_binary_and_record() -> None:
    gold = [(5, 15, "mandatory"), (20, 25, "contextual")]
    preds = [(5, 15, "email"), (40, 50, "secret")]
    # one prediction hits the mandatory gold; the other hits nothing
    sc = metrics.score_binary_record("d", "dom", 60, gold, preds, threshold=0.5)
    assert sc.spans["all"] == metrics.PRF(1, 1, 1)
    assert sc.spans["mandatory"] == metrics.PRF(1, 1, 0)
    assert sc.chars["mandatory"].recall == 1.0  # all 10 mandatory chars covered
    assert sc.mandatory_fully_covered is True


def test_binary_mode_end_to_end(tmp_path: Path) -> None:
    d = _write_necessity_fixture(tmp_path)
    out = tmp_path / "out"
    rc = rb_run.main(["run", "--data-dir", str(d), "--out-dir", str(out), "--chunk-size", "8"])
    assert rc == 0
    results = json.loads((out / "results.json").read_text())
    # auto-detected necessity/binary mode
    assert results["metadata"]["config"]["gold_label_kind"] == "necessity"
    overall = results["overall"]
    assert "character_level_rscore_style" in overall
    assert "span_level_type_agnostic" in overall
    assert "mandatory_protection" in overall
    # the two mandatory secrets are structured -> mandatory char recall should be perfect
    assert overall["character_level_rscore_style"]["mandatory"]["char_recall"] == 1.0
    # predicted-type distribution is reported instead of per-type gold scoring
    assert results["metadata"]["predicted_type_distribution"].get("email", 0) >= 1
    assert (out / "per_domain.csv").is_file()


# --- hand-verified metric trust check ---------------------------------------


def test_char_metric_hand_verified() -> None:
    """Independently hand-computed char P/R/F1 must match the harness exactly.

    text length 20; gold mandatory [0,5), contextual [10,12); pred [0,5),[11,15).
      gold-all mask = {0,1,2,3,4,10,11}   (7 chars)
      pred mask     = {0,1,2,3,4,11,12,13,14} (9 chars)
      TP = {0,1,2,3,4,11} = 6 ; FP = {12,13,14} = 3 ; FN = {10} = 1
      P = 6/9 = 0.6667 ; R = 6/7 = 0.8571 ; F1 = 0.75
      mandatory mask {0..4} fully covered -> mandatory recall = 1.0
    """
    gold = [(0, 5, "mandatory"), (10, 12, "contextual")]
    preds = [(0, 5, "x"), (11, 15, "y")]
    sc = metrics.score_binary_record("d", None, 20, gold, preds, threshold=0.5)
    c = sc.chars["all"]
    assert (c.tp, c.fp, c.fn) == (6, 3, 1)
    assert round(c.precision, 4) == 0.6667
    assert round(c.recall, 4) == 0.8571
    assert c.f1 == 0.75
    assert sc.chars["mandatory"].recall == 1.0
    assert sc.chars["contextual"].recall == 0.5  # 1 of 2 contextual chars (11) covered


def test_char_metric_no_overlap_and_full_miss() -> None:
    # disjoint prediction: zero TP
    sc = metrics.score_binary_record("d", None, 10, [(0, 4, "mandatory")], [(6, 9, "z")], 0.5)
    assert (sc.chars["all"].tp, sc.chars["all"].fn) == (0, 4)
    assert sc.chars["all"].recall == 0.0
    # perfect prediction: full coverage
    sc2 = metrics.score_binary_record("d", None, 10, [(0, 4, "mandatory")], [(0, 4, "z")], 0.5)
    assert sc2.chars["all"].recall == 1.0 and sc2.chars["all"].precision == 1.0
