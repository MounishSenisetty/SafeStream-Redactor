"""Regression tests for the label-anchored identifier cascade and the failure
modes surfaced by the RedactionBench audit.

Covers: label-anchored promotion of otherwise-ambiguous identifiers, value-only
spans (the label word is never redacted), precision guards (no cue -> no
detection), validated-SSN-type preservation, casing/punctuation variants,
adjacent and repeated entities, Unicode context, malformed input, and
streaming/chunk-boundary equivalence for the new tier.
"""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector
from safestream_redactor.entities import EntityType


def _types(text: str) -> set[str]:
    return {d.entity_type.value for d in Redactor().detect(text)}


def _texts(text: str) -> list[str]:
    return [d.text for d in Redactor().detect(text)]


@pytest.mark.parametrize(
    "text,value",
    [
        ("Student ID: 202184673", "202184673"),
        ("Account Number: 102294080031", "102294080031"),
        ("Employee No 59473", "59473"),
        ("Patient MRN: A1234567", "A1234567"),
        ("license number D1234567", "D1234567"),
        ("Member ID 88-2211-09", "88-2211-09"),
    ],
)
def test_labeled_identifier_promoted(text: str, value: str) -> None:
    dets = Redactor().detect(text)
    assert any(d.text == value and d.entity_type is EntityType.ID_NUMBER for d in dets), dets


def test_only_value_span_redacted_not_label() -> None:
    # the label word ("Student ID:") must remain; only the number is redacted
    out = Redactor().redact("Student ID: 202184673 enrolled")
    assert "Student ID:" in out
    assert "202184673" not in out
    assert "enrolled" in out


def test_dob_label_anchored() -> None:
    assert EntityType.DOB.value in _types("DOB: 03/08/1996")
    assert EntityType.DOB.value in _types("date of birth is 1996-03-08")


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("Date of birth: 14 May 1988", "14 May 1988"),
        ("born on 14th of May, 1988 in Leeds", "14th of May, 1988"),
        ("DOB May 14, 1988.", "May 14, 1988"),
        ("Birth date: Sept. 3rd 1990", "Sept. 3rd 1990"),
        ("dob 1 JAN 70", "1 JAN 70"),
    ],
)
def test_dob_textual_dates_are_fully_redacted(text: str, value: str) -> None:
    # the whole date, and only the date, is replaced: no part of it leaks
    assert Redactor().redact(text) == text.replace(value, "[REDACTED]")


@pytest.mark.parametrize("text", ["born in May", "date of birth: May", "DOB: May 14 shipped"])
def test_dob_needs_a_full_date(text: str) -> None:
    assert EntityType.DOB.value not in _types(text)


def test_bare_number_without_cue_is_not_redacted() -> None:
    # precision guard: numbers with no sensitivity cue must be left alone
    assert _types("The build produced 202184673 artifacts in 12345 ms") == set()
    assert _types("version 5.4.2 rev 998877") == set()


def test_invalid_ssn_labeled_is_idnumber_not_ssn() -> None:
    # a 000-area number is not a valid SSN, so the validated SSN type must NOT be
    # claimed; but because the text labels it "ssn" it is still redacted (id_number)
    t = _types("ssn 000-12-3456")
    assert EntityType.SSN.value not in t
    assert EntityType.ID_NUMBER.value in t


def test_valid_ssn_keeps_ssn_type_over_cascade() -> None:
    # the validated deterministic SSN must win overlap resolution
    dets = Redactor().detect("SSN: 123-45-6789")
    ssns = [d for d in dets if "123-45-6789" in d.text]
    assert ssns and ssns[0].entity_type is EntityType.SSN


def test_case_insensitive_cue() -> None:
    assert EntityType.ID_NUMBER.value in _types("STUDENT ID = 202184673")
    assert EntityType.ID_NUMBER.value in _types("student id 202184673")


def test_adjacent_and_repeated_entities() -> None:
    text = "Student ID: 202184673 Account: 556677889 Student ID: 202184673"
    vals = _texts(text)
    assert vals.count("202184673") == 2
    assert "556677889" in vals


def test_unicode_context_preserved() -> None:
    # non-ASCII around the value must not shift offsets or drop the detection
    text = "Café — Student ID: 202184673 — naïve"
    out = Redactor().redact(text)
    assert "202184673" not in out
    assert "Café" in out and "naïve" in out


def test_malformed_input_does_not_crash() -> None:
    for bad in ["", "Student ID:", "Account Number: ", "\x00\x01 ssn \n", "id " * 1000]:
        Redactor().detect(bad)  # must not raise


def test_streaming_equivalence_for_labeled_ids() -> None:
    # a labeled id split across many tiny chunks is detected identically to whole
    from benchmarks.redactionbench import adapter  # local: benchmark-only helper

    r = Redactor()
    text = "Patient record. Student ID: 202184673 and Account Number: 102294080031. " * 30
    streaming = adapter.predict_streaming(r, text, chunk_size=12)
    whole = adapter.predict_whole(r, text)
    key = lambda ps: sorted((p.start, p.end, p.label) for p in ps)  # noqa: E731
    assert key(streaming) == key(whole)


def test_detector_declares_streaming_requirements() -> None:
    req = LabeledIdentifierDetector.requirements
    # overlap must cover the cue->value window so a labeled id split by a chunk
    # boundary is still seen whole
    assert req.required_overlap >= req.left_context
    assert req.max_span >= 32
