"""Target 6: IBAN on by default, URL handling, numbers embedded in longer tokens."""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.entities import EntityType

_ETH = "0x52908400098527886E0F7030069857D2E4169EE7"


def test_iban_is_on_by_default_and_checksum_validated():
    assert Redactor().redact("iban GB82 WEST 1234 5698 7654 32 paid") == "iban [REDACTED] paid"
    assert Redactor().redact("iban GB82WEST12345698765432") == "iban [REDACTED]"
    # a bad check digit is not an IBAN
    assert Redactor().redact("ref GB00WEST12345698765432") == "ref GB00WEST12345698765432"
    assert EntityType.IBAN not in {
        d.entity_type for d in Redactor(types=["email"]).detect("GB82WEST12345698765432")
    }


def test_a_card_run_inside_a_hex_token_is_not_a_card():
    # default: crypto addresses are opt-in, and no card fragment splits the address
    assert Redactor().redact(f"eth {_ETH} ok") == f"eth {_ETH} ok"
    # regional: the whole address is redacted, not a fragment of it
    assert Redactor(use_regional=True).redact(f"eth {_ETH} ok") == "eth [REDACTED] ok"
    # a standalone card is still a card, also glued to a label on one side only
    assert Redactor().redact("card4111111111111111 ok") == "card[REDACTED] ok"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "GET /reset?email=bob%40corp.io&token=ab12cd34ef&lang=en HTTP/1.1",
            "GET /reset?email=[REDACTED]&token=[REDACTED]&lang=en HTTP/1.1",
        ),
        (
            "https://acme.io/cb?code=4/0AY0e-g7XYZ&state=abc",
            "https://acme.io/cb?code=[REDACTED]&state=abc",
        ),
        ("https://acme.io/v?key=Zm9vYmFy123&page=2", "https://acme.io/v?key=[REDACTED]&page=2"),
        ("https://acme.io/u?phone=4155552671", "https://acme.io/u?phone=[REDACTED]"),
        ("https://acme.io/docs?page=2&lang=en", "https://acme.io/docs?page=2&lang=en"),
    ],
)
def test_default_redacts_sensitive_query_values_not_the_url(text, expected):
    assert Redactor().redact(text) == expected


def test_query_only_names_are_not_generic_fields_elsewhere():
    # "key", "code" and "session" count only inside a URL query string
    assert Redactor().redact("code=4021 session=morning") == "code=4021 session=morning"


def test_prose_profile_redacts_every_url_keeping_sentence_punctuation():
    r = Redactor(profile="prose")
    assert r.redact("My website is http://www.OpticalFirm.com.cy/.") == "My website is [REDACTED]."
    assert r.redact("see www.acme.org, then") == "see [REDACTED], then"
    assert r.redact("(https://acme.io/a?b=c)") == "([REDACTED])"
    assert Redactor().redact("see https://acme.io/docs today") == "see https://acme.io/docs today"
