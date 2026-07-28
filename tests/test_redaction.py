"""Redaction policy tests: all modes plus per-type mapping."""

import pytest

from safestream_redactor import EntityType, RedactionMode, RedactionPolicy, Redactor

TEXT = "mail bob@x.io, ssn: 123-45-6789"


def test_default_replace():
    assert Redactor().redact(TEXT) == "mail [REDACTED], ssn: [REDACTED]"


def test_custom_replacement_string():
    policy = RedactionPolicy(replacement="***")
    assert Redactor(policy=policy).redact(TEXT) == "mail ***, ssn: ***"


def test_per_type_replacement_mapping():
    policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
    assert Redactor(policy=policy).redact(TEXT) == "mail <EMAIL>, ssn: [REDACTED]"


def test_partial_masking_keeps_last_n():
    policy = RedactionPolicy(mode=RedactionMode.MASK, mask_keep_last=4)
    out = Redactor(policy=policy).redact("ssn: 123-45-6789")
    assert out == "ssn: *******6789"


def test_masking_keep_zero():
    policy = RedactionPolicy(mode="mask", mask_keep_last=0)
    assert Redactor(policy=policy).redact("ssn: 123-45-6789") == "ssn: ***********"


def test_pseudonymization_is_deterministic():
    policy = RedactionPolicy(mode=RedactionMode.PSEUDONYMIZE, hmac_key=b"k")
    r = Redactor(policy=policy)
    a, b = r.redact("mail bob@x.io"), r.redact("send to bob@x.io please")
    token = a.removeprefix("mail ")
    assert token.startswith("<EMAIL_") and token.endswith(">")
    assert token in b  # same input -> same token
    # different key -> different token
    other = Redactor(policy=RedactionPolicy(mode="pseudonymize", hmac_key=b"k2"))
    assert token not in other.redact("mail bob@x.io")


def test_pseudonymize_requires_key():
    with pytest.raises(ValueError, match="hmac_key"):
        RedactionPolicy(mode="pseudonymize")


def test_pseudonym_token_width_is_configurable_and_defaults_to_64_bits():
    default = RedactionPolicy(mode="pseudonymize", hmac_key=b"k")
    r = Redactor(policy=default)
    token = r.redact("mail bob@x.io").removeprefix("mail ")
    hexpart = token[len("<EMAIL_") : -1]
    assert len(hexpart) == 16  # 16 hex digits = 64 bits, the new default

    wide = RedactionPolicy(mode="pseudonymize", hmac_key=b"k", pseudonym_length=32)
    token = Redactor(policy=wide).redact("mail bob@x.io").removeprefix("mail ")
    assert len(token[len("<EMAIL_") : -1]) == 32


def test_pseudonym_length_bounds_are_validated():
    with pytest.raises(ValueError, match="pseudonym_length"):
        RedactionPolicy(mode="pseudonymize", hmac_key=b"k", pseudonym_length=4)
    with pytest.raises(ValueError, match="pseudonym_length"):
        RedactionPolicy(mode="pseudonymize", hmac_key=b"k", pseudonym_length=128)


def test_adjacent_text_is_preserved():
    out = Redactor().redact("a bob@x.io b 10.0.0.1 c")
    assert out == "a [REDACTED] b [REDACTED] c"
