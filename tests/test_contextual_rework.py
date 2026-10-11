"""Target 9 (CODE_REVIEW F1): suppress triggers are whole words, and demote only
shape-only detections."""

from __future__ import annotations

import importlib.util

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.contextual import ContextualScorer, _word_in
from safestream_redactor.entities import Detection, EntityType

_STRIPE_TEST = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"


@pytest.mark.parametrize(
    "text",
    [
        "latest ssn 555-12-3456",  # "test" inside a word
        "protest bob@corp.io",
        "TestPass bob@corp.io",
        f"key {_STRIPE_TEST}",  # "test" between underscores
    ],
)
def test_a_trigger_inside_a_word_suppresses_nothing(text: str) -> None:
    dets = Redactor(min_confidence=0.0).detect(text)
    assert dets and all(d.meta.get("context") != "suppressed" for d in dets)
    assert "[REDACTED]" in Redactor().redact(text)


def test_a_whole_word_trigger_still_demotes_a_shape_only_value() -> None:
    dets = Redactor(min_confidence=0.0).detect("fake 555-12-3456")
    [ssn] = [d for d in dets if d.entity_type is EntityType.SSN]
    assert ssn.meta["context"] == "suppressed"


@pytest.mark.parametrize(
    "text",
    [
        "TEST card 4111 1111 1111 1111",  # Luhn-valid
        f"test key {_STRIPE_TEST}",  # vendor prefix
        "TEST password: Zx9kQ2mVp7",  # field-anchored
        "example iban GB82 WEST 1234 5698 7654 32",  # checksum
        "$krb5asrep$23$user@EXAMPLE.COM:" + "ab12" * 50,  # hash, realm EXAMPLE
    ],
)
def test_a_file_labelled_test_keeps_validated_and_anchored_values(text: str) -> None:
    dets = Redactor(min_confidence=0.0).detect(text)
    assert dets and all(d.meta.get("context") != "suppressed" for d in dets)
    assert Redactor().redact(text).count("[REDACTED]") == len(dets)


def test_word_in_reads_neighbours_outside_the_range() -> None:
    assert _word_in("a TEST b", 0, 8)
    assert not _word_in("latest", 2, 6)  # the range cuts the word to "test"
    assert not _word_in("test", 0, 3)  # straddles the range end
    assert _word_in("x@EXAMPLE.com", 2, 9)


@pytest.mark.skipif(
    importlib.util.find_spec("safestream_native") is None, reason="native core not built"
)
@pytest.mark.parametrize(
    "text",
    [
        "a TEST 555-12-3456",
        "latest 555-12-3456",
        "la test555-12-3456",
        "test_555-12-3456",
        "x.example 555-12-3456",
        "FA\u212aE 555-12-3456",  # Kelvin sign lower-cases to 'k'
        "fakes 555-12-3456",
        "xxx-xx-1234 555-12-3456",
        "文test 555-12-3456",
        "test",
    ],
)
def test_native_suppress_decision_matches_python(text: str) -> None:
    import safestream_native as sn

    scorer = ContextualScorer()
    spans = [(text.rfind(" ") + 1, len(text)), (0, len(text))]
    flags = sn.adjust_text(text, [(a, b, 0) for a, b in spans], 48, 16)
    assert flags is not None
    for (a, b), flag in zip(spans, flags, strict=True):
        det = Detection(a, b, text[a:b], EntityType.SSN, 0.85, source="deterministic")
        assert bool(flag & 2) == scorer._decide(text, det)[1], (text, a, b)
