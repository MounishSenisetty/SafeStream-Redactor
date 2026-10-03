"""Target 7: identifiers with a published checksum are on by default."""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.regional import (
    ChecksumIdDetector,
    abn_ok,
    acn_ok,
    medicare_ok,
    nric_ok,
    tfn_ok,
)


def rules(text: str) -> list[str]:
    return [d.meta["rule"] for d in ChecksumIdDetector().detect(text)]


def test_validators_accept_valid_and_reject_one_digit_off() -> None:
    assert abn_ok("51824753556") and not abn_ok("51824753557")
    assert acn_ok("005499981") and not acn_ok("005499982")
    assert tfn_ok("123456782") and not tfn_ok("123456789")
    assert medicare_ok("2123456701") and not medicare_ok("2123456711")
    assert nric_ok("S1234567D") and nric_ok("T1234567J") and nric_ok("F1234567N")
    assert not nric_ok("S1234567A") and not nric_ok("M1234567K")
    assert (
        not abn_ok("5182475355")
        and not acn_ok("00549998")
        and not tfn_ok("12345")
        and not medicare_ok("7123456701")
    )


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("nhs 9434765919", "nhs"),
        ("ref 943 476 5919", "nhs"),
        ("ref 2341 2341 2346", "aadhaar"),
        ("ref 51 824 753 556", "au_abn"),
        ("abn: 51824753556", "au_abn"),
        ("ACN 005 499 981", "au_acn"),
        ("tax file number 123 456 782", "au_tfn"),
        ("ref 2123 45670 1", "au_medicare"),
        ("NRIC S1234567D", "sg_nric"),
        ("ref 912-70-1234", "us_itin"),
        ("ITIN 912701234", "us_itin"),
    ],
)
def test_checksummed_ids_are_found(text: str, rule: str) -> None:
    assert rules(text) == [rule]
    assert Redactor().redact(text).endswith("[REDACTED]")


@pytest.mark.parametrize(
    "text",
    [
        "order 51824753556",  # a valid ABN as a bare run needs its cue
        "order 123456782",  # a valid TFN without a cue is just a number
        "acn 005499982",  # bad check digit
        "ref 912-93-1234",  # 93 is not an IRS ITIN group
        "ref 912701234",  # a bare ITIN needs its cue
        "ref S1234567A",  # bad NRIC check letter
    ],
)
def test_uncued_or_invalid_numbers_are_left_alone(text: str) -> None:
    assert rules(text) == []


def test_naming_a_checksum_type_enables_only_that_tier() -> None:
    assert Redactor(types=["nhs_number"]).redact("nhs 9434765919") == "nhs [REDACTED]"
    assert Redactor(types=["email"]).redact("nhs 9434765919") == "nhs 9434765919"
