"""Regression gates for the kernel hardening fixes.

Each fix is an optimisation or a data-integrity correction that must not change
what gets detected, so every test here is either a differential check against
the original (reference) behaviour or a direct check of the corrected property.
Complexity regressions are asserted structurally (call counts) or with bounds
two to three orders of magnitude above the fixed cost, never tight timings.
"""

from __future__ import annotations

import random
import re
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_redactor import Redactor
from safestream_redactor.detectors import labeled_id
from safestream_redactor.detectors.deterministic import _PATTERNS, _email_scan
from safestream_redactor.detectors.labeled_id import _MAX_VALUE, LabeledIdentifierDetector
from safestream_redactor.engine import stream_windows
from safestream_redactor.entities import Detection, EntityType, resolve_overlaps

_EMAIL = next(p for p in _PATTERNS if p.entity_type is EntityType.EMAIL).regex


# --- resolve_overlaps: O(n log n), identical to the original greedy ---------


def _resolve_reference(detections: list[Detection]) -> list[Detection]:
    """The original O(n^2) implementation, kept as the oracle."""
    ordered = sorted(detections, key=lambda d: (-d.confidence, d.start - d.end, d.start))
    kept: list[Detection] = []
    for cand in ordered:
        if not any(cand.overlaps(k) for k in kept):
            kept.append(cand)
    kept.sort(key=lambda d: d.start)
    return kept


_span = st.tuples(
    st.integers(0, 60), st.integers(0, 14), st.sampled_from([0.45, 0.6, 0.75, 0.9, 1.0])
)


@settings(max_examples=400, deadline=None)
@given(st.lists(_span, max_size=40))
def test_resolve_overlaps_matches_reference(spans):
    # zero-length spans included: they are the edge case for the bisection
    dets = [Detection(s, s + n, "x", EntityType.EMAIL, c) for s, n, c in spans]
    got = resolve_overlaps(list(dets))
    want = _resolve_reference(list(dets))
    assert [id(d) for d in got] == [id(d) for d in want]


def test_resolve_overlaps_scales_subquadratically():
    dets = [Detection(i * 5, i * 5 + 4, "x", EntityType.EMAIL, 0.9) for i in range(50_000)]
    started = time.perf_counter()
    assert len(resolve_overlaps(dets)) == 50_000
    # ~0.1 s at O(n log n); the quadratic version took minutes here
    assert time.perf_counter() - started < 10


# --- EMAIL: linear '@'-anchored scanner, identical to finditer --------------


@settings(max_examples=2000, deadline=None)
@given(st.text(alphabet="ab.Z9@-_%+ é\n", max_size=60))
def test_email_scan_matches_finditer(text):
    want = [(m.span(), m.group()) for m in _EMAIL.finditer(text)]
    assert [(m.span(), m.group()) for m in _email_scan(_EMAIL, text)] == want


def test_email_scan_matches_finditer_seeded_fuzz():
    rng = random.Random(20260925)
    parts = ["a", "b.", "x@", "@", "co", ".io", "-", "_", "%", "+", " ", "é", "\n", "9"]
    for _ in range(3000):
        text = "".join(rng.choice(parts) for _ in range(rng.randint(0, 30)))
        want = [m.span() for m in _EMAIL.finditer(text)]
        assert [m.span() for m in _email_scan(_EMAIL, text)] == want, text


@pytest.mark.parametrize(
    "hostile",
    ["a." * 100_000 + " @", "x@" + "a-" * 100_000, ("u.v" * 50 + "@") * 2_000],
)
def test_email_scan_is_linear_on_hostile_input(hostile):
    started = time.perf_counter()
    list(_email_scan(_EMAIL, hostile))
    # linear: well under a second; finditer needs minutes on the 200K cases
    assert time.perf_counter() - started < 5


# --- labeled-identifier tier: no ReDoS, spans within the declared bound -----

_OLD_SEP = r"(?:\s*(?:number|num|no|id|code|#|:|=|-|\.|is|of)\b)*\s*[:=#\-.]?\s*"


def test_labeled_separator_matches_the_original_language():
    rng = random.Random(7)
    parts = [" ", "\t", "\n", ":", "-", ".", "#", "=", "no", "is", "number", "x", "1"]
    old = re.compile(_OLD_SEP + r"(\d+)", re.IGNORECASE)
    new = re.compile(labeled_id._SEP + r"(\d+)", re.IGNORECASE)
    for _ in range(20_000):
        text = "".join(rng.choice(parts) for _ in range(rng.randint(0, 12)))
        a, b = old.match(text), new.match(text)
        assert (a and (a.span(), a.span(1))) == (b and (b.span(), b.span(1))), text


@pytest.mark.parametrize("cue", ["ssn", "account:", "phone no.", "Student ID"])
def test_labeled_identifier_is_linear_on_whitespace_runs(cue):
    started = time.perf_counter()
    LabeledIdentifierDetector().detect(cue + " " * 200_000 + "x")
    # was O(n^2): ~19 s at 32K spaces, i.e. ~12 min at 200K
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize("text", ["phone 1" + " 1" * 6000, "account 1" + "-1" * 6000])
def test_labeled_identifier_spans_respect_declared_max_span(text):
    detections = LabeledIdentifierDetector().detect(text)
    assert detections
    assert all(d.end - d.start <= _MAX_VALUE for d in detections)
    assert LabeledIdentifierDetector.requirements.max_span == _MAX_VALUE


# --- streaming engine: bounded rescans for any input chunking ---------------


def test_small_chunks_are_coalesced_before_detection():
    calls = 0

    def detect(text: str) -> list[Detection]:
        nonlocal calls
        calls += 1
        return []

    lines = ["x" * 99 + "\n"] * 10_000  # 1 MB as 100-char lines
    out = "".join(seg for seg, _ in stream_windows(lines, detect, 8192))
    assert out == "".join(lines)
    # one pass per >= overlap chars emitted: ~122 passes, not ~10_000
    assert calls <= len(out) // 8192 + 2


def test_line_fed_stream_equals_whole_text_redaction():
    rng = random.Random(3)
    rows = [
        f"id={i} mail=u{i}@corp.io ip=10.0.{i % 256}.{rng.randint(0, 255)} "
        f"card 4111 1111 1111 1111 ssn: 123-45-6789 tok=ghp_{'a1' * 18}\n"
        for i in range(3000)
    ]
    text = "".join(rows)
    r = Redactor(load_plugins=False)
    assert "".join(r.redact_stream(iter(rows))) == r.redact(text)


# --- line endings are preserved byte-for-byte ------------------------------


@pytest.mark.parametrize("workers", [None, 4])
def test_redact_file_preserves_crlf_and_lone_cr(tmp_path, monkeypatch, workers):
    import safestream_redactor.parallel as parallel

    monkeypatch.setattr(parallel, "MIN_RANGE_BYTES", 4096)
    body = "mail a@b.io ok\r\nplain line\rnext\n" * 2000
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_bytes(body.encode())
    Redactor(load_plugins=False).redact_file(src, dst, workers=workers)
    assert dst.read_bytes() == body.replace("a@b.io", "[REDACTED]").encode()


def test_cli_stdin_honours_encoding_and_line_endings(capsysbinary, monkeypatch):
    import io
    import sys

    from safestream_redactor.cli import main

    raw = "Grüße a@b.io\r\nnext\r".encode("latin-1")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="ascii"))
    assert main(["redact", "-", "-o", "-", "--encoding", "latin-1"]) == 0
    assert capsysbinary.readouterr().out == "Grüße [REDACTED]\r\nnext\r".encode("latin-1")


def test_pinned_buffer_waits_for_more_input_before_rescanning():
    pinned_passes = 0

    def detect(text: str) -> list[Detection]:
        nonlocal pinned_passes
        if "t" not in text:  # until the 20th char, one detection pins the buffer
            pinned_passes += 1
            return [Detection(0, len(text) - 1, text[:-1], EntityType.CUSTOM, 1.0)]
        return []

    text = "abcdefghijklmnopqrstuvwx"
    out = "".join(seg for seg, _ in stream_windows(iter(text), detect, 4))
    assert out == text
    # passes at 8, 12, 16 buffered chars; rescanning per 1-char chunk made it 12
    assert pinned_passes == 3


def test_labeled_identifier_ignores_a_cue_beyond_its_window():
    far = "ssn" + " " * 200 + "123456789"
    assert LabeledIdentifierDetector().detect(far) == []
    assert LabeledIdentifierDetector().detect("ssn: 123456789")


def test_cli_stdio_text_only_streams_and_truncated_input(capsysbinary, monkeypatch):
    import io
    import sys

    from safestream_redactor.cli import main

    # text-only stand-ins (no .buffer) still work, e.g. when embedded
    monkeypatch.setattr(sys, "stdin", io.StringIO("mail a@b.io\n"))
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert main(["redact", "-", "-o", "-"]) == 0
    assert sys.stdout.getvalue() == "mail [REDACTED]\n"
    monkeypatch.undo()

    # a multi-byte sequence cut off at EOF decodes to U+FFFD, like a file read
    raw = b"mail a@b.io \xe2\x82"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
    assert main(["redact", "-", "-o", "-"]) == 0
    assert capsysbinary.readouterr().out == "mail [REDACTED] �".encode()
