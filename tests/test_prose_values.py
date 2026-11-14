"""Prose profile: years, money, number/year references, and the spaCy prose mode."""

from __future__ import annotations

import pytest

from safestream_redactor.detectors.ner import _generic, _with_title
from safestream_redactor.detectors.prose_values import ProseValueDetector
from safestream_redactor.entities import EntityType
from safestream_redactor.redactor import Redactor


@pytest.mark.parametrize(
    ("text", "value", "etype"),
    [
        ("a revised offer of GBP 147,682.42 was made", "GBP 147,682.42", EntityType.MONEY),
        ("a fine of £1,000 and penalty points", "£1,000", EntityType.MONEY),
        ("an award of EUR 25 million in damages", "EUR 25 million", EntityType.MONEY),
        ("repurchased for 235,000 Swedish crowns", "235,000 Swedish crowns", EntityType.MONEY),
        ("an application (no. 47676/99) against", "47676/99", EntityType.ID_NUMBER),
        ("The applicant was born in 1954 and lives", "1954", EntityType.DATE),
    ],
)
def test_values(text: str, value: str, etype: EntityType) -> None:
    found = ProseValueDetector().detect(text)
    assert [(d.text, d.entity_type) for d in found] == [(value, etype)]
    assert text[found[0].start : found[0].end] == value


@pytest.mark.parametrize(
    "text", ["version 3.2019 of the tool", "room 12345", "path a/1999/b", "ratio 1/2"]
)
def test_no_value(text: str) -> None:
    assert ProseValueDetector().detect(text) == []


def test_off_by_default_on_in_prose() -> None:
    line = "born in 1954, fined GBP 1,000 in case 47676/99"
    assert "1954" in Redactor().redact(line)
    out = Redactor(profile="prose").redact(line)
    assert "1954" not in out and "1,000" not in out and "47676/99" not in out


def test_years_follow_the_date_setting() -> None:
    assert "1954" not in Redactor(profile="prose").redact("born in 1954")
    assert "1954" in Redactor(profile="prose", use_dates=False).redact("born in 1954")


def test_declared_bounds_keep_the_default_overlap() -> None:
    assert Redactor(profile="prose").min_safe_overlap == Redactor().min_safe_overlap


def test_streamed_equals_whole_in_prose_profile() -> None:
    text = (
        "The applicant, born in 1954, lodged application no. 47676/99 and was awarded "
        "GBP 147,682.42; a further 235,000 Swedish crowns followed in 2003.\n"
    ) * 60
    r = Redactor(profile="prose", chunk_size=8192)
    whole = r.redact(text)
    for size in (1, 7, 100, 4096):
        chunks = (text[i : i + size] for i in range(0, len(text), size))
        assert "".join(r.redact_stream(chunks)) == whole


def test_title_kept_with_name() -> None:
    text = "represented by Mr Derek Walton of the Office"
    start = text.index("Derek")
    assert text[_with_title(text, start, start + 12) :].startswith("Mr Derek")
    plain = "a report by Derek Walton"
    s2 = plain.index("Derek")
    assert _with_title(plain, s2, s2 + 12) == s2


@pytest.mark.parametrize(
    ("span", "generic"),
    [
        ("the Court", True),
        ("Government", True),
        ("FACTS", False),
        ("the Grand Chamber", True),
        ("the Falun Municipal Council", False),
        ("Blackspur", False),
        ("IBM", False),
    ],
)
def test_generic_institutions(span: str, generic: bool) -> None:
    assert _generic(span) is generic
