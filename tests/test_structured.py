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
        # a username line holds one token: a transcript speaker label is not one
        ("Username: bob42", "Username: [REDACTED]"),
        ("Username: bob42 logged in", "Username: bob42 logged in"),
        ("User1: Thank you, User2. I agree.", "User1: Thank you, User2. I agree."),
        ("**User2**: Absolutely, User1.", "**User2**: Absolutely, User1."),
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


# --- secret fields (target 3) ---------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("password = 'open sesame'", "open sesame"),  # letters-only, with a space
        ('db_password := "Tr0ub4dor&3"', "Tr0ub4dor&3"),
        ('"AdminPassword" : "correcthorse"', "correcthorse"),
        ("$cfg->Password = 'hunter22';", "hunter22"),
        (":password => 'swordfish1',", "swordfish1"),
        ('<add key="SmtpPassword" value="Pa55w0rd!"/>', "Pa55w0rd!"),
        ("The admin password is 'letmein99'", "letmein99"),
        ("Server=db;Database=app;Pwd=Zx9!q2;Encrypt=true", "Zx9!q2"),
        ("Endpoint=https://x.example.io;Id=a1;Secret=QmFzZTY0U2VjcmV0PQ==", "QmFzZTY0U2VjcmV0PQ=="),
        ("export API_TOKEN=tok_9f8e7d6c5b4a", "tok_9f8e7d6c5b4a"),
        ("client_secret: s3cr3t-value  # rotate quarterly", "s3cr3t-value"),
    ],
)
def test_secret_field_values_are_fully_redacted(text, value):
    assert _redacted(text, value)


@pytest.mark.parametrize(
    "value",
    ["None", "null", "nil", '""', "''", "${DB_PASS}", "$DB_PASS", "%DB_PASS%",
     "{{ db_pass }}", 'os.environ["DB_PASS"]', "process.env.DB_PASS",
     'getenv("DB_PASS")', "os.getenv('DB_PASS')", "<redacted>", "****", "true"],
)  # fmt: skip
def test_secret_references_and_placeholders_are_never_redacted(value):
    for text in (f"password = {value}", f'"password": {value}', f"password: {value}"):
        assert Redactor().redact(text) == text, text


@pytest.mark.parametrize(
    "text",
    ["token_type: Bearer", "password_policy: strict", "passwordExpiryDays: 90", "bypass: cache",
     "compass: north", "password_reset_required: false"],
)  # fmt: skip
def test_secret_suffix_rule_leaves_lookalike_fields_alone(text):
    assert Redactor().redact(text) == text


def test_connection_string_user_and_password_are_both_redacted():
    out = Redactor().redact("Server=db;Database=app;User=svc;Pwd=Zx9!q2;Encrypt=true")
    assert out == "Server=db;Database=app;User=[REDACTED];Pwd=[REDACTED];Encrypt=true"


def test_label_gated_rules_skip_references():
    for text in ("api_key = process.env.KEY", "password = ${DB_PASS}", "secret: ****"):
        assert Redactor().redact(text) == text, text


def test_uri_userinfo_username_and_password_are_both_redacted():
    out = Redactor().redact("postgresql://report_user:S3cret@db.internal:5432/app")
    assert out == "postgresql://[REDACTED]:[REDACTED]@db.internal:5432/app"


def test_username_suffix_fields():
    assert (
        Redactor().redact("REACT_APP_AUTH_USERNAME=bowie") == "REACT_APP_AUTH_USERNAME=[REDACTED]"
    )
    assert Redactor().redact('smtp_username: "mailer01"') == 'smtp_username: "[REDACTED]"'
    assert field_type("display_name") is None
