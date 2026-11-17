"""Regression tests for the follow-up fixes: names in prose, table headers, Indian
identifiers and URL passwords that contain "@" (all under the default settings)."""

from __future__ import annotations

import pytest

import safestream_redactor.parallel as par
from safestream_redactor import Redactor
from safestream_redactor.detectors.columns import header_spec
from safestream_redactor.parallel import redact_file_parallel

R = "[REDACTED]"


@pytest.fixture(scope="module")
def redactor() -> Redactor:
    return Redactor()


def _persons(r: Redactor, text: str) -> list[str]:
    return [d.text for d in r.detect(text) if d.entity_type.value == "person"]


# --- names in prose -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("my name is suresh", "suresh"),
        ("My name is Suresh Kumar and I live here", "Suresh Kumar"),
        ("I am Suresh", "Suresh"),
        ("Dear Suresh,", "Suresh"),
        ("Hi Priya!", "Priya"),
        ("Good morning Priya, how are you", "Priya"),
        ("Dear 村上 健二, your parcel shipped.", "村上 健二"),
        ("Thanks, Suresh", "Suresh"),
        ("Best regards,\nSuresh Kumar", "Suresh Kumar"),
        ("Mr Suresh Kumar", "Suresh Kumar"),
        ("Mr. suresh kumar", "suresh kumar"),
        ("Smt. Lakshmi Devi", "Lakshmi Devi"),
        ("Shri Ramesh", "Ramesh"),
        ("Ms Priya Sharma joined", "Priya Sharma"),
        ("Created by Suresh Kumar", "Suresh Kumar"),
        ("Signed by: Suresh Kumar", "Suresh Kumar"),
        ("Author: Suresh Kumar", "Suresh Kumar"),
        ("Reviewer: Suresh Kumar", "Suresh Kumar"),
        ("From: Suresh Kumar", "Suresh Kumar"),
        ('From: "Suresh Kumar" <suresh@example.com>', "Suresh Kumar"),
    ],
)
def test_names_in_prose(redactor, text, name):
    assert name in _persons(redactor, text)


def test_display_names_in_a_recipient_list(redactor):
    out = redactor.redact("To: Suresh Kumar <s@example.io>, Priya <p@example.io>")
    assert out == f"To: {R} <{R}>, {R} <{R}>"


@pytest.mark.parametrize(
    "text",
    [
        "my name is not important",
        "I am sure it works",
        "I am Happy",
        "Dear Sir,",
        "Dear Team,",
        "Hi all,",
        "Hi there!",
        "Thanks, team",
        "Regards,\nThe Support Team",
        "latency 500 ms delay",
        "Dr. who",
        "created by system",
        "Created by Jenkins",
        "updated by admin",
        "From: 2024-01-01 To: 2024-02-01",
        "The test is good",
    ],
)
def test_ordinary_sentences_keep_their_words(redactor, text):
    assert redactor.redact(text) == text


# --- delimited tables typed by their header ---------------------------------------------

CSV = (
    "name,email,phone,city,status\n"
    "Suresh Kumar,a@b.com,9876543210,Bangalore,active\n"
    '"Priya, R",p@x.io,+44 20 7946 0958,London,ok\n'
    "bob,b@c.io,12,,new\n"
)
CSV_OUT = (
    f'name,email,phone,city,status\n{R},{R},{R},{R},active\n"{R}",{R},{R},{R},ok\n{R},{R},12,,new\n'
)


def test_csv_columns_are_typed_by_the_header(redactor):
    assert redactor.redact(CSV) == CSV_OUT


def test_tsv_and_name_only_columns(redactor):
    tsv = "first_name\tlast_name\tssn\nsuresh\tkumar\t123-45-6789\n"
    assert redactor.redact(tsv) == f"first_name\tlast_name\tssn\n{R}\t{R}\t{R}\n"


@pytest.mark.parametrize(
    "first_line",
    ["a,b,c", "1,2,3", "name: suresh", "hello, world", "id,count,total"],
)
def test_lines_that_are_not_a_personal_data_header(first_line):
    assert header_spec(first_line + "\nx,y,z\n") is None


def test_header_detection_ignores_a_bom_and_crlf():
    spec = header_spec("﻿Name;Email\r\nx;y\r\n")
    assert spec is not None and spec.delimiter == ";" and spec.names == ("Name", "Email")


@pytest.mark.parametrize("size", [1, 3, 7, 64, 1000])
def test_csv_streaming_matches_whole_text(redactor, size):
    text = CSV * 30
    pieces = [text[i : i + size] for i in range(0, len(text), size)]
    assert "".join(redactor.redact_stream(pieces)) == redactor.redact(text)


def test_csv_rows_far_below_the_header(redactor):
    # the header is far outside the window that holds the last rows
    text = "name,email\n" + "Suresh Kumar,a@b.com\n" * 20000
    r = Redactor(chunk_size=4096, overlap=1024, allow_unsafe_overlap=True)
    out = "".join(r.redact_stream([text[i : i + 997] for i in range(0, len(text), 997)]))
    assert out == "name,email\n" + f"{R},{R}\n" * 20000


def test_csv_type_filter():
    assert (
        Redactor(types=["email"]).redact(CSV).splitlines()[1]
        == "Suresh Kumar,[REDACTED],9876543210,Bangalore,active"
    )


def test_csv_parallel_is_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setattr(par, "MIN_RANGE_BYTES", 4096)
    src = tmp_path / "in.csv"
    src.write_text(CSV + "Ravi Teja,r@t.io,98765 43210,Pune,ok\n" * 3000)
    r = Redactor(chunk_size=1024, overlap=1024, allow_unsafe_overlap=True)
    seq, parallel_out = tmp_path / "seq.csv", tmp_path / "par.csv"
    r.redact_file(src, seq)
    outcome = redact_file_parallel(r, str(src), str(parallel_out), workers=4)
    assert outcome.ranges > 1 and not outcome.fell_back
    assert parallel_out.read_bytes() == seq.read_bytes()
    assert b"Ravi" not in seq.read_bytes()


# --- Indian identifiers -------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "234567890124",  # bare Aadhaar, passes Verhoeff
        "2345 6789 0124",
        "ABCPE1234F",  # PAN
        "PAN ABCPE1234F",
        "9876543210",
        "98765 43210",
        "09876543210",
        "Contact suresh at 9876543210",
    ],
)
def test_indian_identifiers(redactor, text):
    assert redactor.redact(text) != text
    assert not any(ch.isdigit() for ch in redactor.redact(text).replace("PAN ", ""))


@pytest.mark.parametrize(
    "text",
    [
        "234567890123",  # fails Verhoeff
        "order 9876543210",
        "txn id 9876543210",
        "x9876543210",
        "98765432101",  # eleven digits
        "1699999999",  # an epoch second, starts with 1
    ],
)
def test_numbers_that_are_not_indian_identifiers(redactor, text):
    assert redactor.redact(text) == text


def test_nhs_number_is_not_read_as_a_mobile(redactor):
    (det,) = redactor.detect("nhs 9434765919")
    assert det.entity_type.value == "nhs_number"


# --- URL passwords holding "@" -----------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "out"),
    [
        (
            "postgres://admin:s3cretP@ss@db.example.com:5432/app",
            f"postgres://{R}:{R}@db.example.com:5432/app",
        ),
        ("mongodb://user:p@ss@h1/db", f"mongodb://{R}:{R}@h1/db"),
        ("https://user:hunter22@example.com/path", f"https://{R}:{R}@example.com/path"),
    ],
)
def test_url_password_with_at_sign(redactor, url, out):
    assert redactor.redact(url) == out


@pytest.mark.parametrize(
    "text",
    [
        "Customer: Hi, I was charged twice for order 48213.",
        "Customer: I was charged twice",
        "Patient: ok thanks",
    ],
)
def test_a_role_label_before_a_chat_line_is_not_a_name(redactor, text):
    assert redactor.redact(text) == text
