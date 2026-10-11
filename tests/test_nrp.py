"""Target 8: nationality / religious-group words (NRP) in the prose profile."""

from __future__ import annotations

from safestream_redactor import Redactor
from safestream_redactor.entities import EntityType


def test_prose_profile_redacts_demonyms_phrases_plurals_and_religions() -> None:
    r = Redactor(profile="prose")
    assert (
        r.redact("Two Swedish and three Americans met a South African.")
        == "Two [REDACTED] and three [REDACTED] met a [REDACTED]."
    )
    assert r.redact("Sikhs, Jews; an Englishman") == "[REDACTED], [REDACTED]; an [REDACTED]"
    assert {d.entity_type for d in r.detect("a norwegian")} == {EntityType.NRP}


def test_ambiguous_lowercase_words_and_substrings_are_not_nrp() -> None:
    r = Redactor(profile="prose")
    assert (
        r.redact("polish the floor, then Polish food") == "polish the floor, then [REDACTED] food"
    )
    assert r.redact("the indianapolis job") == "the indianapolis job"


def test_nrp_is_off_by_default_and_enabled_by_naming_it() -> None:
    assert Redactor().redact("Two Swedish tourists") == "Two Swedish tourists"
    assert Redactor(types=["nrp"]).redact("Two Swedish tourists") == "Two [REDACTED] tourists"
