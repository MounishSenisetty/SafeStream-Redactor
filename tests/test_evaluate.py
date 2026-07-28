"""Smoke tests for the real-corpus evaluation harness.

These verify the scoring plumbing (per-type tp/fp/fn, label mapping, restriction
to annotated types), not detection accuracy — accuracy is what the harness
measures when pointed at a real corpus, which isn't bundled.
"""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "evaluate", Path(__file__).resolve().parent.parent / "benchmarks" / "evaluate.py"
)
assert _spec and _spec.loader
evaluate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluate)


def test_parse_label_map():
    assert evaluate.parse_label_map("PERSON=person, US_SSN=ssn") == {
        "PERSON": "person",
        "US_SSN": "ssn",
    }
    assert evaluate.parse_label_map("") == {}


def test_score_record_counts_per_type():
    gold = [(0, 5, "email"), (10, 21, "ssn")]
    preds = [(0, 5, "email"), (30, 40, "email")]  # one hit, one false positive
    out = evaluate.score_record(gold, preds, {"email", "ssn"})
    assert out["email"] == (1, 1, 0)  # tp, fp, fn
    assert out["ssn"] == (0, 0, 1)  # missed entirely


def test_score_restricts_to_eval_types():
    # a predicted type outside the annotated set is neither tp nor fp
    gold = [(0, 5, "email")]
    preds = [(0, 5, "email"), (6, 9, "person")]
    out = evaluate.score_record(gold, preds, {"email"})
    assert set(out) == {"email"}
    assert out["email"] == (1, 0, 0)


def test_prf():
    assert evaluate.prf(0, 0, 0) == (0.0, 0.0, 0.0)
    p, r, f = evaluate.prf(3, 1, 1)
    assert round(p, 3) == 0.75 and round(r, 3) == 0.75 and round(f, 3) == 0.75


def test_spans_match_half_overlap_threshold():
    assert evaluate.spans_match((0, 10), (5, 15))  # 5/10 of gold overlapped
    assert not evaluate.spans_match((0, 6), (5, 15))  # 1/10 of gold overlapped
