"""Regional / checksum-validated recognizers (opt-in tier)."""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.regional import (
    RegionalDetector,
    base58check_ok,
    bech32_ok,
    iban_ok,
    nhs_ok,
    verhoeff_ok,
)
from safestream_redactor.entities import EntityType

DET = RegionalDetector()


def found(text: str) -> list[tuple[str, str]]:
    return [(d.entity_type.value, d.text) for d in DET.detect(text)]


# --- checksum primitives, against published vectors ----------------------------


def test_iban_mod97_and_country_length() -> None:
    assert iban_ok("GB82WEST12345698765432")
    assert iban_ok("DE89370400440532013000")
    assert iban_ok("FR1420041010050500013M02606")
    assert not iban_ok("GB82WEST12345698765433")  # one digit off
    assert not iban_ok("GB82WEST1234569876543")  # wrong length for GB
    assert not iban_ok("XX82WEST12345698765432")  # unknown country: rejected, not guessed


def test_nhs_mod11() -> None:
    assert nhs_ok("9434765919")
    assert not nhs_ok("9434765918")
    assert not nhs_ok("1000000010")  # mod-11 remainder 10 is never valid


def test_verhoeff_published_vector() -> None:
    assert verhoeff_ok("2363")  # the classic worked example: 236 + check digit 3
    assert not verhoeff_ok("2364")


def test_bitcoin_checksums() -> None:
    assert base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")  # genesis block address
    assert base58check_ok("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
    assert not base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert bech32_ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")  # BIP-173
    assert bech32_ok("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")  # BIP-350
    assert not bech32_ok("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")


# --- detection ---------------------------------------------------------------


def test_detects_validated_identifiers_in_text() -> None:
    text = (
        "pay GB82 WEST 1234 5698 7654 32 or 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "or 0x52908400098527886E0F7030069857D2E4169EE7; nhs 943 476 5919; pan ABCPE1234F; "
        "ni number AB 12 34 56 C"
    )
    kinds = {k for k, _ in found(text)}
    assert kinds == {"iban", "crypto_address", "nhs_number", "in_pan", "uk_nino"}
    assert ("iban", "GB82 WEST 1234 5698 7654 32") in found(text)


def test_aadhaar_needs_a_valid_check_digit_and_a_cue_or_spacing() -> None:
    body = "23412341234"
    good = next(body + str(c) for c in range(10) if verhoeff_ok(body + str(c)))
    spaced = f"{good[:4]} {good[4:8]} {good[8:]}"
    assert ("in_aadhaar", spaced) in found(f"id {spaced}")
    assert ("in_aadhaar", good) in found(f"Aadhaar: {good}")
    assert found(f"order {good} shipped") == []  # a bare 12-digit run is not enough
    bad = body + str((int(good[-1]) + 1) % 10)
    assert found(f"Aadhaar: {bad}") == []


def test_bare_ten_digit_numbers_are_not_nhs_numbers() -> None:
    assert found("order 9434765919 shipped") == []
    assert ("nhs_number", "9434765919") in found("NHS number: 9434765919")


def test_false_positive_suppression() -> None:
    noise = [
        "GB82WEST12345698765433",  # bad IBAN checksum
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",  # bad base58check
        "0x1234",  # not an address
        "AB 12 34 56 E",  # NINO suffix must be A-D
        "GB 12 34 56 C",  # GB is a prefix HMRC never issues
        "ABCDE1234F",  # PAN 4th letter is not a holder type
        "the ABCPE1234FG suffix",  # embedded in a longer token
    ]
    for item in noise:
        assert found(item) == [], item


def test_identifiers_embedded_in_longer_tokens_are_ignored() -> None:
    assert found("xGB82WEST12345698765432") == []
    assert found("GB82WEST12345698765432x") == []


# --- integration -------------------------------------------------------------


def test_regional_tier_is_opt_in() -> None:
    text = "iban GB82 WEST 1234 5698 7654 32"
    assert "GB82" in Redactor().redact(text)
    assert "GB82" not in Redactor(use_regional=True).redact(text)
    assert "GB82" not in Redactor(types=["iban"]).redact(text)  # asking for the type enables it


def test_regional_tier_streams_identically_across_chunk_boundaries() -> None:
    r = Redactor(use_regional=True, overlap=512, chunk_size=64, allow_unsafe_overlap=True)
    text = ("pad " * 15 + "GB82 WEST 1234 5698 7654 32 and pan ABCPE1234F\n") * 10
    for size in (1, 3, 17, 64):
        got = "".join(r.redact_stream(text[i : i + size] for i in range(0, len(text), size)))
        assert got == r.redact(text)
    assert "GB82" not in r.redact(text)


def test_declared_streaming_requirements_cover_every_span() -> None:
    req = RegionalDetector.requirements
    assert req.max_span >= 42  # a spaced 34-character IBAN
    assert req.left_context >= 40  # the cue-word window


@pytest.mark.parametrize(
    "kind", ["iban", "crypto_address", "uk_nino", "nhs_number", "in_aadhaar", "in_pan"]
)
def test_new_types_have_a_severity(kind: str) -> None:
    from safestream_redactor.severity import severity_for

    assert severity_for(EntityType(kind)) in {"critical", "high", "medium", "low"}


# --- IBAN must be in a canonical print form (fix F) ---------------------------------


@pytest.mark.parametrize(
    "good",
    [
        "GB82WEST12345698765432",  # electronic format
        "GB82 WEST 1234 5698 7654 32",  # print format: groups of four, last may be short
        "DE89 3704 0044 0532 0130 00",
        "NO93 8601 1117 947",  # 15 characters: three full groups and a group of three
    ],
)
def test_iban_accepts_the_canonical_forms(good: str) -> None:
    assert [d.text for d in DET.detect(f"iban {good} end")] == [good]


@pytest.mark.parametrize(
    "bad",
    [
        "GB82 W E S T 1 2 3 4 5 6 9 8 7 6 5 4 3 2",  # a space after every character
        "GB82WEST 1234 5698 7654 32",  # mixed: grouped only after the first eight
        "GB82  WEST 1234 5698 7654 32",  # double space
        "GB82 WES T123 4569 8765 432",  # groups not of four
        "GB82 WEST 1234 5698 7654 3 2",  # last group split
    ],
)
def test_iban_rejects_non_canonical_spacing(bad: str) -> None:
    assert [d.text for d in DET.detect(f"iban {bad} end") if d.entity_type.value == "iban"] == []


def test_longest_iban_span_fits_the_declared_requirement() -> None:
    # Malta, 31 characters, printed in groups of four: 31 + 7 separators
    assert RegionalDetector.requirements.max_span >= 31 + (31 - 1) // 4
