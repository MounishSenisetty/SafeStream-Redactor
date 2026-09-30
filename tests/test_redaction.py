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


# --------------------------------------------------------------------------
# mask mode must never leave a short value readable
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Bob", "**b"),  # was "Bob": keep_last=4 >= len revealed it whole
        ("Alice", "***ce"),  # was "*lice"
        ("abcd", "**cd"),
        ("123-45-6789", "*******6789"),  # long values keep the full keep_last
    ],
)
def test_mask_reveals_at_most_half(value, expected):
    policy = RedactionPolicy(mode="mask", mask_keep_last=4)
    assert Redactor(custom_words=[value], policy=policy).redact(f"x {value} y") == (
        f"x {expected} y"
    )


def test_mask_single_char_is_fully_masked():
    r = Redactor(custom_patterns=[r"\bQ\b"], policy=RedactionPolicy(mode="mask"))
    assert r.redact("grade Q here") == "grade * here"


def test_empty_mask_char_rejected():
    # "" would delete the span instead of hiding it, changing the output shape
    with pytest.raises(ValueError, match="mask_char"):
        RedactionPolicy(mode="mask", mask_char="")


def test_hmac_key_accepts_str():
    as_str = Redactor(policy=RedactionPolicy(mode="pseudonymize", hmac_key="k"))
    as_bytes = Redactor(policy=RedactionPolicy(mode="pseudonymize", hmac_key=b"k"))
    assert as_str.redact(TEXT) == as_bytes.redact(TEXT)


# --------------------------------------------------------------------------
# constructor arguments that used to corrupt output silently
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"chunk_size": 0}, "chunk_size"),  # used to write an EMPTY output file
        ({"chunk_size": -1}, "chunk_size"),  # used to read the whole file at once
        ({"chunk_size": True}, "chunk_size"),
        ({"chunk_size": 1.5}, "chunk_size"),
        ({"overlap": -1}, "overlap"),
        ({"min_confidence": 1.5}, "min_confidence"),
        ({"min_confidence": -0.1}, "min_confidence"),
        ({"min_confidence": "0.5"}, "min_confidence"),
    ],
)
def test_invalid_streaming_arguments_rejected(kwargs, match):
    with pytest.raises(ValueError, match=match):
        Redactor(**kwargs)


def test_chunk_size_one_is_still_correct(tmp_path):
    src = tmp_path / "in.txt"
    src.write_text(TEXT)
    out = tmp_path / "out.txt"
    Redactor(chunk_size=1).redact_file(src, out)
    assert out.read_text() == Redactor().redact(TEXT)
