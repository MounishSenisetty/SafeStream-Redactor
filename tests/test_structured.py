"""Structured-field tier: the field name types the value; only the value is redacted."""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.structured import (
    StructuredFieldDetector,
    field_type,
    is_placeholder,
)
from safestream_redactor.entities import EntityType


def _redacted(text: str, value: str, **kwargs) -> bool:
    """The value, and nothing but the value, is replaced (no partial leak)."""
    return Redactor(**kwargs).redact(text) == text.replace(value, "[REDACTED]", 1)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('{"LastName": "Arap", "x": 1}', "Arap"),
        ("{'GivenName2': 'Vick'}", "Vick"),
        ("<GivenName2>Vick</GivenName2>", "Vick"),
        ("<Phone>006472290.7501</Phone>", "006472290.7501"),
        ('"telephone_number": "+12-70.163-4650",', "+12-70.163-4650"),
        ("   Postcode: 'SN4 9AB'", "SN4 9AB"),
        ("- Driver's License: GV34719EX", "GV34719EX"),
        ("**Date of Birth:** 14/05/1988", "14/05/1988"),
        ("2. Passport Number: X1234567", "X1234567"),
        ("user=bob42 action=login", "bob42"),
        ('"username": "midhat25"', "midhat25"),
        ("Street Address: 48334 36 rue de la Paix", "48334 36 rue de la Paix"),
        ('{"city": "Cambridge"}', "Cambridge"),
        ("phone=4155552671&ref=x", "4155552671"),
    ],
)
def test_field_values_are_fully_redacted(text, value):
    assert _redacted(text, value)


def test_field_names_normalise_across_conventions():
    for key in ("LastName", "last_name", "last-name", "Last Name", "LASTNAME", "lastName2"):
        assert field_type(key) is EntityType.PERSON, key
    assert field_type("Driver's License") is EntityType.ID_NUMBER
    assert field_type("dob") is EntityType.DOB
    assert field_type("handle") is EntityType.USERNAME
    for generic in ("id", "title", "region", "status", "type"):
        assert field_type(generic) is None, generic


@pytest.mark.parametrize(
    "text",
    [
        '{"name": "api-gateway", "state": "RUNNING"}',  # service name, status word
        '{"name": "payments"}',  # not person-shaped
        '{"user": null}',
        '"phone": "n/a"',
        "username: ${USERNAME}",
        "username: $USER",
        "username: %USERNAME%",
        'username: "{{ user }}"',
        "phone: <redacted>",
        "phone: ****",
        "username = os.environ['USER']",
        "username = process.env.USER",
        "username = getenv('USER')",
        'username: ""',
        "country: default",
        '{"zip": true}',
    ],
)
def test_placeholders_and_log_noise_are_left_alone(text):
    assert Redactor().redact(text) == text


@pytest.mark.parametrize(
    "value",
    ["null", "None", "nil", "", "${X}", "$X", "%X%", "{{ x }}", "<redacted>", "****",
     "[REDACTED]", "os.environ['X']", "process.env.X", "getenv('X')", "os.getenv('X')"],
)  # fmt: skip
def test_is_placeholder(value):
    assert is_placeholder(value)


@pytest.mark.parametrize("value", ["hunter2", "secret", "changeme", "Arap", "+44 20 7946 0958"])
def test_real_values_are_not_placeholders(value):
    assert not is_placeholder(value)


def test_sex_and_title_fields_only_in_the_prose_profile():
    text = '{"Gender": "Female", "honorific": "Dr"}'
    assert Redactor().redact(text) == text
    assert (
        Redactor(profile="prose").redact(text)
        == '{"Gender": "[REDACTED]", "honorific": "[REDACTED]"}'
    )
    assert Redactor(profile="prose", use_prose_fields=False).redact(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # a line value stops at the next label and at what its type can be
        ("Name: John Smith Phone: 415 555 2671", "Name: [REDACTED] Phone: [REDACTED]"),
        (
            "Passport Number: X1234567 issued in Leeds",
            "Passport Number: [REDACTED] issued in Leeds",
        ),
        ("DOB: May 14 shipped", "DOB: May 14 shipped"),  # not a full date
        ("Username: bob42 logged in", "Username: [REDACTED] logged in"),
    ],
)
def test_line_values_are_cut_to_what_their_type_can_be(text, expected):
    assert Redactor().redact(text) == expected


def test_only_the_value_is_redacted_never_the_field_name():
    out = Redactor().redact('{"FirstName": "Nduka", "LastName": "Okafor"}')
    assert out == '{"FirstName": "[REDACTED]", "LastName": "[REDACTED]"}'


def test_types_filter_scopes_the_tier():
    text = '{"username": "midhat25"}'
    assert Redactor(types=["email"]).redact(text) == text
    assert Redactor(types=["username"]).redact(text) == '{"username": "[REDACTED]"}'


def test_detector_is_window_pure_and_bounded():
    det = StructuredFieldDetector()
    long_value = "A" + "b" * 300
    assert det.detect(f'{{"name": "{long_value}"}}') == []  # value over the bound
    assert det.requirements.max_span == 128
