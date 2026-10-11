"""The benchmark harness scorer and corpus plumbing (benchmarks/harness.py, corpora/)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
np = pytest.importorskip("numpy")

from benchmarks import corpora, harness  # noqa: E402
from benchmarks.corpora import Doc, Gold  # noqa: E402
from benchmarks.corpora import split as splitter  # noqa: E402


def test_score_doc_char_entity_and_mandatory_counts():
    #            0123456789012345678901234
    doc = Doc(
        "d",
        "call 555-0100 or mail a@b",
        [
            Gold(5, 13, "PHONE_NUMBER", "mandatory"),
            Gold(22, 25, "EMAIL_ADDRESS", "contextual"),
        ],
    )
    # phone fully covered (and 2 extra chars), email half covered
    c = harness.score_doc(doc, [(5, 15, "PHONE_NUMBER"), (22, 23, "EMAIL_ADDRESS")])
    assert (c["char_tp"], c["char_fp"], c["char_fn"]) == (9, 2, 2)
    assert (c["ent_total"], c["ent_covered"]) == (2, 1)  # a half-masked email leaks
    assert (c["mand_total"], c["mand_cov"], c["mand_noleak_docs"]) == (8, 8, 1)
    assert c["PHONE_NUMBER|tp_partial"] == 1 and c["PHONE_NUMBER|tp_strict"] == 0
    assert c["EMAIL_ADDRESS|tp_partial"] == 0  # 1 of 3 chars < 50% of the gold span
    assert c["*|gold"] == 2 and c["*|pred"] == 2


def test_fp_doc_rate_counts_flagged_gold_free_documents():
    docs = [Doc("pos", "key", [Gold(0, 3, "SECRET")]), Doc("n1", "uuid"), Doc("n2", "sha")]
    out = harness.evaluate(docs, {"s": [[(0, 3, "SECRET")], [(0, 4, "SECRET")], []]}, resamples=0)
    assert out["systems"]["s"]["point"]["fp_doc_rate"] == 0.5  # one of two negatives flagged


def test_presidio_scope_ignores_types_presidio_lacks():
    #            0123456789012345678901
    doc = Doc(
        "d",
        "user bob42 mail a@b.io",
        [
            Gold(5, 10, "USERNAME"),  # Presidio has no USERNAME: out of scope
            Gold(16, 22, "EMAIL_ADDRESS"),
        ],
    )
    # redacting the username neither helps nor hurts the Presidio-scope score
    with_user = harness.evaluate(
        [doc], {"s": [[(5, 10, "USERNAME"), (16, 22, "EMAIL")]]}, resamples=0
    )["systems"]["s"]["point"]
    without = harness.evaluate([doc], {"s": [[(16, 22, "EMAIL")]]}, resamples=0)["systems"]["s"][
        "point"
    ]
    for k in ("scope_char_p", "scope_char_r", "scope_fully_redacted"):
        assert with_user[k] == without[k] == 1.0, k
    # while the all-gold metric does reward it
    assert with_user["entity_recall_covered"] == 1.0 > without["entity_recall_covered"]


def test_partial_match_is_one_to_one():
    golds = [(0, 4), (5, 9)]
    # one prediction covering both golds matches only one of them
    assert harness._match(golds, [(0, 9)]) == (1, 0)
    assert harness._match(golds, [(0, 4), (5, 9)]) == (2, 2)


def test_evaluate_points_cis_and_paired_differences():
    docs = [Doc(f"d{i}", "x" * 10, [Gold(0, 5, "ID")]) for i in range(20)]
    perfect = [[(0, 5, "ID")] for _ in docs]
    half = [[(0, 5, "ID")] if i % 2 else [] for i in range(20)]
    out = harness.evaluate(docs, {"a": perfect, "b": half}, resamples=200)
    a, b = out["systems"]["a"], out["systems"]["b"]
    assert a["point"]["char_r"] == 1.0 and b["point"]["char_r"] == 0.5
    lo, hi = b["ci95"]["char_r"]
    assert lo < 0.5 < hi
    assert a["per_type"]["ID"]["r_strict"] == 1.0
    diff = out["paired_diff_ci95"]["a - b"]["char_r"]
    assert diff[0] > 0  # a's lead is outside the noise: CI of the difference excludes 0


def test_split_is_deterministic_disjoint_and_grouped():
    docs = [Doc(f"np-pos-np.x.{r}-{k}", "t", []) for r in range(6) for k in range(3)]
    corpus = corpora.Corpus("secrets", docs, [])
    corpus.sources = []
    a = splitter.make_manifest(corpus)
    b = splitter.make_manifest(corpus)
    assert a["dev"] == b["dev"] and not set(a["dev"]) & set(a["test"])
    assert len(a["dev"]) + len(a["test"]) == len(docs)
    side = {i: ("dev" if i in a["dev"] else "test") for i in a["dev"] + a["test"]}
    for r in range(6):  # every example of one rule lands on the same side
        assert len({side[f"np-pos-np.x.{r}-{k}"] for k in range(3)}) == 1


def test_load_refuses_a_changed_source(tmp_path, monkeypatch):
    src = tmp_path / "src.txt"
    src.write_text("v1")
    corpus = corpora.Corpus("toy", [Doc("a", "hello", [Gold(0, 9, "X")])], [src])
    monkeypatch.setitem(
        corpora.LOADERS,
        "toy",
        lambda: corpora.Corpus("toy", [Doc("a", "hello", [Gold(0, 9, "X")])], [src]),
    )
    monkeypatch.setattr(corpora, "SPLITS", tmp_path)
    (tmp_path / "toy.json").write_text(json.dumps(splitter.make_manifest(corpus)))
    loaded = corpora.load("toy", "all")
    assert loaded.docs[0].spans[0].end == 5  # out-of-range gold is clipped...
    assert loaded.skipped  # ...and reported, never silently
    src.write_text("v2")
    with pytest.raises(ValueError, match="source changed"):
        corpora.load("toy", "dev")


def test_conll_loader_builds_character_spans(tmp_path, monkeypatch):
    d = tmp_path / "conll2003"
    d.mkdir()
    (d / "label.json").write_text(json.dumps({"O": 0, "B-PER": 1, "I-PER": 2, "B-MISC": 3}))
    (d / "test.json").write_text(
        json.dumps({"tokens": ["John", "Smith", "likes", "Python"], "tags": [1, 2, 0, 3]}) + "\n"
    )
    monkeypatch.setattr(corpora, "EXTERNAL", tmp_path)
    doc = corpora.load_conll2003().docs[0]
    assert [(doc.text[s.start : s.end], s.type) for s in doc.spans] == [
        ("John Smith", "PERSON"),
        ("Python", "MISC"),  # unmapped labels keep their name: nothing is dropped
    ]
