"""Hash / Encrypt / Fictionalize operators and the Deanonymizer."""

from __future__ import annotations

import re

import pytest

from safestream_redactor import Deanonymizer, RedactionPolicy, Redactor
from safestream_redactor.cli import main
from safestream_redactor.detectors.deterministic import luhn_ok
from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.operators import encrypt_token, fictionalize, hash_token

KEY = "k" * 32
TEXT = "mail bob@corp.example card 4111 1111 1111 1111 ip 10.1.2.3 ssn 123-45-6789 ok\n"


def _det(value: str, kind: EntityType) -> Detection:
    return Detection(0, len(value), value, kind, 1.0)


# --- hash ------------------------------------------------------------------


def test_hash_is_deterministic_salted_and_hides_the_value() -> None:
    a = RedactionPolicy(mode="hash", hash_salt="s1").render(
        _det("bob@corp.example", EntityType.EMAIL)
    )
    b = RedactionPolicy(mode="hash", hash_salt="s1").render(
        _det("bob@corp.example", EntityType.EMAIL)
    )
    c = RedactionPolicy(mode="hash", hash_salt="s2").render(
        _det("bob@corp.example", EntityType.EMAIL)
    )
    assert a == b != c
    assert re.fullmatch(r"<EMAIL:H:[0-9a-f]{16}>", a)
    assert "bob" not in a


def test_hash_algorithm_is_restricted() -> None:
    with pytest.raises(ValueError, match="hash_algorithm"):
        RedactionPolicy(mode="hash", hash_algorithm="md5")
    assert hash_token("sha512", b"", "email", "x", 32) != hash_token(
        "sha256", b"", "email", "x", 32
    )


# --- encrypt / deanonymize ---------------------------------------------------


def test_encrypt_requires_a_long_enough_key() -> None:
    with pytest.raises(ValueError, match="encrypt_key"):
        RedactionPolicy(mode="encrypt")
    with pytest.raises(ValueError, match="at least 16"):
        RedactionPolicy(mode="encrypt", encrypt_key="short")


def test_encrypt_round_trips_through_the_deanonymizer() -> None:
    r = Redactor(policy=RedactionPolicy(mode="encrypt", encrypt_key=KEY))
    out = r.redact(TEXT)
    for secret in ("bob@corp.example", "4111 1111 1111 1111", "123-45-6789"):
        assert secret not in out
    d = Deanonymizer(KEY)
    assert d.restore(out) == TEXT
    assert d.restored >= 3 and d.failed == 0


def test_encrypt_is_deterministic_so_equal_values_stay_equal() -> None:
    p = RedactionPolicy(mode="encrypt", encrypt_key=KEY)
    det = _det("bob@corp.example", EntityType.EMAIL)
    assert p.render(det) == p.render(det)
    assert p.render(det) != p.render(_det("eve@corp.example", EntityType.EMAIL))


def test_wrong_key_and_tampering_fail_closed() -> None:
    token = encrypt_token(KEY.encode(), "email", "bob@corp.example")
    wrong = Deanonymizer("z" * 32)
    assert wrong.restore(token) == token and wrong.failed == 1  # left untouched, never garbage
    flipped = token[:-3] + ("A" if token[-3] != "A" else "B") + token[-2:]
    d = Deanonymizer(KEY)
    assert d.restore(flipped) == flipped and d.failed == 1
    # the entity type is authenticated: relabelling a token must not decrypt
    relabelled = token.replace("<EMAIL:E:", "<PHONE:E:")
    d2 = Deanonymizer(KEY)
    assert d2.restore(relabelled) == relabelled and d2.failed == 1


def test_restore_stream_handles_tokens_split_across_chunks() -> None:
    r = Redactor(policy=RedactionPolicy(mode="encrypt", encrypt_key=KEY))
    out = r.redact(TEXT * 3)
    for size in (1, 2, 7, 64):
        d = Deanonymizer(KEY)
        chunks = (out[i : i + size] for i in range(0, len(out), size))
        assert "".join(d.restore_stream(chunks)) == TEXT * 3


# --- fictionalize ----------------------------------------------------------


def test_fictionalize_needs_a_key_and_is_deterministic() -> None:
    with pytest.raises(ValueError, match="hmac_key"):
        RedactionPolicy(mode="fictionalize")
    assert fictionalize(b"k", "email", "a@b.co") == fictionalize(b"k", "email", "a@b.co")
    assert fictionalize(b"k", "email", "a@b.co") != fictionalize(b"j", "email", "a@b.co")


@pytest.mark.parametrize(
    ("kind", "value", "shape"),
    [
        ("email", "bob@corp.example", r"user[0-9a-f]{8}@example\.com"),
        ("phone", "415-555-2671", r"\+1-555-01\d\d"),
        ("ssn", "123-45-6789", r"9\d\d-\d\d-\d{4}"),  # area 9xx is never issued
        ("ipv4", "10.1.2.3", r"(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+"),  # TEST-NET
        ("ipv6", "fe80::1", r"2001:db8::[0-9a-f]+"),  # documentation prefix
    ],
)
def test_fictionalize_produces_type_shaped_reserved_values(
    kind: str, value: str, shape: str
) -> None:
    fake = fictionalize(b"k", kind, value)
    assert re.fullmatch(shape, fake), fake
    assert fake != value


def test_fictionalized_card_is_luhn_valid_and_not_the_original() -> None:
    fake = fictionalize(b"k", "credit_card", "4111 1111 1111 1111")
    assert luhn_ok(re.sub(r"\D", "", fake)) and fake != "4111 1111 1111 1111"


def test_fictionalize_never_echoes_secrets_of_unknown_types() -> None:
    fake = fictionalize(b"k", "aws_key", "AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" not in fake and fake.startswith("<AWS_KEY_")


# --- the streaming/parallel equivalence guarantee must survive new operators ---


@pytest.mark.parametrize(
    "policy",
    [
        RedactionPolicy(mode="hash", hash_salt="s"),
        RedactionPolicy(mode="encrypt", encrypt_key=KEY),
        RedactionPolicy(mode="fictionalize", hmac_key="k"),
    ],
    ids=["hash", "encrypt", "fictionalize"],
)
def test_streaming_equals_whole_for_every_operator(policy: RedactionPolicy) -> None:
    r = Redactor(policy=policy, overlap=256, chunk_size=64, allow_unsafe_overlap=True)
    text = TEXT * 20
    for size in (1, 5, 33, 200):
        got = "".join(r.redact_stream(text[i : i + size] for i in range(0, len(text), size)))
        assert got == r.redact(text)


# --- CLI ---------------------------------------------------------------------


def test_cli_encrypt_then_deanonymize_round_trips(tmp_path) -> None:
    src, enc, back = tmp_path / "in.txt", tmp_path / "enc.txt", tmp_path / "back.txt"
    src.write_text(TEXT, encoding="utf-8")
    assert (
        main(["redact", str(src), "-o", str(enc), "--mode", "encrypt", "--encrypt-key", KEY]) == 0
    )
    assert "bob@corp.example" not in enc.read_text(encoding="utf-8")
    assert main(["deanonymize", str(enc), "-o", str(back), "--encrypt-key", KEY]) == 0
    assert back.read_text(encoding="utf-8") == TEXT


def test_cli_encrypt_without_a_key_is_refused(tmp_path, capsys) -> None:
    src = tmp_path / "in.txt"
    src.write_text(TEXT)
    with pytest.raises(SystemExit):
        main(["redact", str(src), "-o", "-", "--mode", "encrypt"])


def test_cli_deanonymize_reports_undecryptable_tokens(tmp_path, capsys) -> None:
    src = tmp_path / "enc.txt"
    src.write_text(encrypt_token(b"a" * 32, "email", "x@y.zz"))
    out = tmp_path / "o.txt"
    rc = main(["deanonymize", str(src), "-o", str(out), "--encrypt-key", "b" * 32])
    assert rc != 0  # a wrong key must not look like success
    assert "could not be decrypted" in capsys.readouterr().err


def test_cli_key_can_come_from_the_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SAFESTREAM_ENCRYPT_KEY", KEY)
    src, enc = tmp_path / "in.txt", tmp_path / "enc.txt"
    src.write_text(TEXT)
    assert main(["redact", str(src), "-o", str(enc), "--mode", "encrypt"]) == 0
    assert "bob@corp.example" not in enc.read_text()
