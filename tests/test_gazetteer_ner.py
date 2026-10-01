"""Regression tests for the model-free gazetteer/context name+org detector.

Covers the failure modes called out for the semantic tier: names adjacent to
punctuation, titles, multi-token names, initials, accented names, CJK/non-Latin
(a documented limitation), organizations, names split across chunk boundaries,
multiple adjacent entities, overlapping semantic/deterministic candidates, and
low-confidence ambiguous names — plus the precision guards that keep ordinary
prose from being redacted.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from safestream_redactor import Redactor  # noqa: E402
from safestream_redactor.detectors.gazetteer_ner import GazetteerNameDetector  # noqa: E402
from safestream_redactor.entities import EntityType  # noqa: E402


def _names(text: str, **kw: object) -> list[str]:
    # the gazetteer tier alone, without the spaCy tier that is on by default
    r = Redactor(use_gazetteer=True, use_ner=False, **kw)  # type: ignore[arg-type]
    return [d.text for d in r.detect(text) if d.entity_type in (EntityType.PERSON, EntityType.ORG)]


def test_honorific_and_titles() -> None:
    assert "Laramie Woods" in _names("Dr. Laramie Woods signed the form.")
    assert "Jane Smith" in _names("Prof. Jane Smith teaches here.")
    assert "Robert King" in _names("Officer Robert King responded.")


def test_professional_suffix() -> None:
    assert "Leona Qureshi" in _names("seen by Leona Qureshi, MD today")
    assert "Alan Poe" in _names("Alan Poe, PhD, presented.")


def test_form_field_cue() -> None:
    assert "James Wilson" in _names("Patient Name: James Wilson arrived.")
    assert "Keith Tanner" in _names("Signature of Student: Keith Tanner")


def test_multi_token_and_initials() -> None:
    assert "John A. Rivera" in _names("Dear John A. Rivera, thank you.")
    assert any("Mary" in n for n in _names("Attn: Mary Beth Callaghan"))


def test_names_adjacent_to_punctuation() -> None:
    assert "Melissa Schettler" in _names("Dear Melissa Schettler, your appeal is received.")
    assert "Diane Luna" in _names("(signed) Dr. Diane Luna.")


def test_accented_names() -> None:
    # accented Latin names are supported by the token class
    got = _names("Dr. Brändá Solís examined the patient.")
    assert any("Br" in n for n in got), got


def test_cjk_names_are_a_documented_limitation() -> None:
    # non-Latin scripts need the neural NER tier; the gazetteer should simply not
    # fire (no crash, no false positive), which is the documented behaviour.
    got = _names("Dear 村上 健二, your parcel shipped.")
    assert all("村上" not in n for n in got)


def test_organization_names() -> None:
    assert "Acme Systems, Inc" in _names("Acme Systems, Inc filed the report.")
    assert "University of Texas" in _names("enrolled at University of Texas last fall")


def test_multiple_adjacent_entities() -> None:
    got = _names("Dr. Jane Smith and Dr. Robert King co-signed.")
    assert "Jane Smith" in got and "Robert King" in got


def test_overlapping_semantic_and_deterministic_kept_correctly() -> None:
    # an email (deterministic, high confidence) next to a cued name: both survive,
    # and the email keeps its type (deterministic wins any overlap).
    r = Redactor(use_gazetteer=True)
    dets = r.detect("Contact Name: James Wilson at james.wilson@corp.io")
    types = {d.entity_type for d in dets}
    assert EntityType.EMAIL in types
    assert any(d.entity_type is EntityType.PERSON and "James Wilson" in d.text for d in dets)


def test_low_confidence_gazetteer_drops_at_higher_threshold() -> None:
    # a bare gazetteer match with NO cue (conf 0.55) is present at the default...
    assert "James Wilson" in _names("I saw James Wilson yesterday", min_confidence=0.5)
    # ...but a caller favouring precision can raise the threshold to drop it
    assert "James Wilson" not in _names("I saw James Wilson yesterday", min_confidence=0.6)


def test_precision_guards_on_ordinary_prose() -> None:
    # sentence-initial capitals, months, salutations, org-word-as-common-noun
    for benign in [
        "The System processed the request quickly.",
        "We met in April for the March update.",
        "Dear Sir or Madam, please review.",
        "This Report covers the Systems overview.",
        "Send Money now to continue.",
    ]:
        assert _names(benign) == [], (benign, _names(benign))


def test_only_value_span_not_cue_is_redacted() -> None:
    out = Redactor(use_gazetteer=True).redact("Patient Name: James Wilson checked in")
    assert "Patient Name:" in out
    assert "James Wilson" not in out


def test_streaming_equivalence_names_split_across_chunks() -> None:
    from benchmarks.redactionbench import adapter

    r = Redactor(use_gazetteer=True)
    text = "Dear Melissa Schettler. Patient Name: James Wilson, MD at Acme Systems, Inc. " * 20
    key = lambda ps: sorted((p.start, p.end, p.label) for p in ps)  # noqa: E731
    for chunk in (8, 16, 32):
        assert key(adapter.predict_streaming(r, text, chunk)) == key(adapter.predict_whole(r, text))


def test_detector_declares_streaming_requirements() -> None:
    req = GazetteerNameDetector.requirements
    assert req.required_overlap >= req.left_context
    assert req.max_span >= 32
