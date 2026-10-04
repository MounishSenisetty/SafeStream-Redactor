"""Phase 1: full UK postcodes are addresses by default."""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("London SW1A 2AA today", "London [REDACTED] today"),
        ("Postcode: M15 7JJ", "Postcode: [REDACTED]"),
        ("Bristol, BS16 4EG, UK", "Bristol, [REDACTED], UK"),
        ("ref OX12 only", "ref OX12 only"),  # an outward code alone is ambiguous
        ("BS164EG", "BS164EG"),  # no space: an identifier as often as a postcode
        ("hash SHA1 0AB", "hash SHA1 0AB"),  # glued to a longer word
        ("code AB1 2CI", "code AB1 2CI"),  # inward letters never use C I K M O V
    ],
)
def test_full_uk_postcodes_are_redacted(text: str, expected: str) -> None:
    assert Redactor().redact(text) == expected


def test_postcodes_follow_the_address_type() -> None:
    assert Redactor(types=["email"]).redact("SW1A 2AA") == "SW1A 2AA"
    assert Redactor(types=["address"]).redact("SW1A 2AA") == "[REDACTED]"
