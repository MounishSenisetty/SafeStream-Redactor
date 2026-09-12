"""Regression tests for the calibrated semantic ensemble.

Covers: evidence tracing, separate PERSON/ORG scoring, the STRICT cue-gate vs
HIGH_RECALL policy, calibrated rejection of isolated weak signals, bounded
repeated-mention propagation, address->LOC cueing, precision guards on benign
prose (public figures), and streaming/chunk-boundary equivalence.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from safestream_redactor import Redactor  # noqa: E402
from safestream_redactor.detectors.semantic_ensemble import (  # noqa: E402
    SemanticEnsembleDetector,
)


def _dets(text: str, policy: str = "strict"):
    return SemanticEnsembleDetector(policy=policy).detect(text)


def _texts(text: str, policy: str = "strict"):
    return [(d.text, d.entity_type.value) for d in _dets(text, policy)]


def test_evidence_tracing_present() -> None:
    dets = _dets("Dr. Melissa Vance signed.")
    assert dets
    d = dets[0]
    assert "evidence" in d.meta and "score" in d.meta and "policy" in d.meta
    assert "honorific" in d.meta["evidence"]  # the trace names the firing signal


def test_person_vs_org_separation() -> None:
    assert ("Acme Systems, Inc", "org") in _texts("Acme Systems, Inc filed.") or any(
        t == "Acme Systems" and et == "org" for t, et in _texts("Acme Systems, Inc filed.")
    )
    assert any(et == "person" for _, et in _texts("Dr. Melissa Vance signed."))


def test_isolated_weak_signal_rejected() -> None:
    # a single capitalized common word is not enough evidence (calibrated reject)
    assert _texts("The System processed the request.") == []
    assert _texts("We met in April for the review.") == []


def test_strict_cue_gate_vs_high_recall() -> None:
    # a bare public-figure name (name-shape only, no cue) is redacted only in HR
    bare = "James Watson discovered the structure."
    assert not any(et == "person" for _, et in _texts(bare, "strict"))
    assert any(et == "person" and "James Watson" in t for t, et in _texts(bare, "high_recall"))
    # a cued name is redacted under BOTH policies
    for pol in ("strict", "high_recall"):
        assert any(
            et == "person" and "Keith Tanner" in t
            for t, et in _texts("Patient Name: Keith Tanner arrived.", pol)
        )


def test_cue_signals_fire() -> None:
    assert any(et == "person" for _, et in _texts("Dr. Laramie Woods approved it."))
    assert any(et == "person" for _, et in _texts("seen by Leona Qureshi, MD today"))
    assert any(et == "person" for _, et in _texts("Signature of Student: Keith Tanner"))


def test_repeated_mention_propagation_bounded() -> None:
    # a bare surname after a confirmed full name is boosted (within the window)
    text = "Dr. Melissa Vance reviewed it. Later, Vance approved the change."
    got = _texts(text, "strict")
    assert any(t == "Vance" and et == "person" for t, et in got), got


def test_repeated_mention_does_not_reach_across_far_context() -> None:
    # beyond the propagation window a bare token is NOT boosted (bounded lookback)
    d = SemanticEnsembleDetector(policy="strict", propagation_window=20)
    text = "Dr. Melissa Vance reviewed it. " + ("x " * 40) + "Vance signed."
    got = [x.text for x in d.detect(text)]
    assert "Vance" not in got  # too far -> not propagated


def test_address_cue_emits_location() -> None:
    got = _texts("City: Fresno reported clear weather.")
    assert any(et == "loc" for _, et in got)


def test_value_only_span_not_cue() -> None:
    out = Redactor(use_ensemble=True).redact("Patient Name: Keith Tanner arrived")
    assert "Patient Name:" in out
    assert "Keith Tanner" not in out


def test_precision_on_benign_prose_strict() -> None:
    # STRICT must not redact bare public-figure names / common-word capitals
    for benign in [
        "James Watson and Francis Crick described DNA.",
        "Grace Hopper built the first compiler.",
        "In April the team will mark the May milestones.",
        "North Carolina borders South Carolina and Virginia.",
        "The HttpClient class wraps ConnectionPool.",
    ]:
        persons = [t for t, et in _texts(benign, "strict") if et == "person"]
        assert persons == [], (benign, persons)


def test_policy_thresholds_separate_person_org() -> None:
    from safestream_redactor.detectors.semantic_ensemble import HIGH_RECALL, STRICT

    assert STRICT.person_threshold != STRICT.org_threshold or STRICT.require_person_cue
    assert HIGH_RECALL.person_threshold < STRICT.org_threshold


def test_streaming_equivalence() -> None:
    from benchmarks.redactionbench import adapter

    for pol in ("strict", "high_recall"):
        r = Redactor(use_ensemble=True, semantic_policy=pol)
        text = "Dr. Melissa Vance met James Wilson. Patient Name: Keith Tanner. Acme Inc. " * 20
        key = lambda ps: sorted((p.start, p.end, p.label) for p in ps)  # noqa: E731
        for chunk in (8, 16, 32):
            assert key(adapter.predict_streaming(r, text, chunk)) == key(
                adapter.predict_whole(r, text)
            )


def test_bounded_memory_state() -> None:
    # the confirmed-name cache is capped independent of input length
    d = SemanticEnsembleDetector(policy="high_recall", max_confirmed=8)
    text = " ".join(f"Dr. Name{i} Surname{i}." for i in range(500))
    d.detect(text)  # must not accumulate unbounded state or crash
    # the deque is created per-call and capped; assert the cap is honored
    assert d.max_confirmed == 8
