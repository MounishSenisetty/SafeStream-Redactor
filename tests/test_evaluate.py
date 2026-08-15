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


# --- WI-4/5: statistics, adapters, loaders --------------------------------


def test_regex_baseline_adapter_finds_email_and_ssn():
    spans = evaluate.regex_baseline_adapter()("mail a@b.com ssn 123-45-6789")
    labels = {t for _, _, t in spans}
    assert "email" in labels and "ssn" in labels


def test_safestream_adapter_returns_mapped_spans():
    spans = evaluate.safestream_adapter()("contact bob@x.io")
    assert any(t == "email" for _, _, t in spans)


def test_bootstrap_ci_brackets_point_estimate():
    # a perfect system: F1 == 1.0 on every record
    per_record = [{"email": (1, 0, 0)} for _ in range(20)]
    point, lo, hi = evaluate.bootstrap_f1_ci(per_record, {"email"}, resamples=200, seed=1)
    assert point == 1.0
    assert lo <= point <= hi


def test_paired_bootstrap_detects_a_real_gap():
    good = [{"email": (1, 0, 0)} for _ in range(30)]  # F1 = 1.0
    bad = [{"email": (0, 0, 1)} for _ in range(30)]  # F1 = 0.0
    p = evaluate.paired_bootstrap_pvalue(good, bad, {"email"}, resamples=200, seed=1)
    assert p < 0.05
    # identical systems: no significant difference
    p_same = evaluate.paired_bootstrap_pvalue(good, good, {"email"}, resamples=200, seed=1)
    assert p_same == 1.0


def test_load_conll_reconstructs_char_spans(tmp_path):
    # "Alice met Bob in Paris" with PER, PER, LOC
    conll = tmp_path / "c.txt"
    conll.write_text(
        "Alice NNP B-NP B-PER\n"
        "met VBD B-VP O\n"
        "Bob NNP B-NP B-PER\n"
        "in IN B-PP O\n"
        "Paris NNP B-NP B-LOC\n"
    )
    records = evaluate.load_conll(conll)
    assert len(records) == 1
    text, spans = records[0]
    assert text == "Alice met Bob in Paris"
    # two separate B-PER tokens are two entities; offsets recover the tokens exactly
    assert sorted(spans) == [(0, 5, "person"), (10, 13, "person"), (17, 22, "loc")]


def test_load_conll_multiword_entity(tmp_path):
    conll = tmp_path / "c.txt"
    conll.write_text("New NNP B-NP B-LOC\nYork NNP I-NP I-LOC\ncity NN I-NP O\n")
    text, spans = evaluate.load_conll(conll)[0]
    assert text == "New York city"
    assert (0, 8, "loc") in spans  # "New York"


def test_load_presidio_json(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(
        '[{"full_text": "hi bob", '
        '"spans": [{"entity_type": "PERSON", "start_position": 3, "end_position": 6}]}]'
    )
    records = evaluate.load_presidio_json(p)
    assert records == [("hi bob", [(3, 6, "PERSON")])]


def test_collect_errors_categorises_fn_and_fp():
    records = [("ssn 123-45-6789 here", [(4, 15, "ssn")])]
    # an adapter that predicts the wrong span -> both a FP and a FN
    errs = evaluate.collect_errors(records, lambda t: [(0, 3, "ssn")], {"ssn"}, limit=5)
    assert errs["ssn"]["fn"] and errs["ssn"]["fp"]
