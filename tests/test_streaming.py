"""Streaming engine tests, most importantly chunk-boundary correctness."""

import pytest

from safestream_redactor import Redactor


def chunked(text: str, size: int):
    for i in range(0, len(text), size):
        yield text[i : i + size]


TEXT = (
    "Report by jane.doe@corp.example.com on 2024-01-01.\n"
    "Customer card 4111 1111 1111 1111 charged. ssn: 123-45-6789.\n"
    "Server 192.168.1.100 leaked key AKIAIOSFODNN7EXAMPLE yesterday.\n"
) * 5


@pytest.mark.parametrize("chunk_size", [1, 3, 7, 16, 64, 256, 10_000])
def test_streaming_equals_whole_text(chunk_size):
    """Streaming output must be identical to whole-text redaction for ANY chunking."""
    r = Redactor(overlap=128)
    assert "".join(r.redact_stream(chunked(TEXT, chunk_size))) == r.redact(TEXT)


def test_entity_split_across_two_chunks():
    """An email cut in half by a chunk boundary must still be redacted."""
    text = "hello jane.doe@example.org bye"
    cut = text.index("@")  # boundary right through the entity
    chunks = [text[:cut], text[cut:]]
    r = Redactor(overlap=64)
    assert "".join(r.redact_stream(chunks)) == "hello [REDACTED] bye"


def test_ssn_split_across_three_chunks():
    chunks = ["ssn: 123", "-45-", "6789 end"]
    out = "".join(Redactor(overlap=32).redact_stream(chunks))
    assert out == "ssn: [REDACTED] end"


def test_detection_spanning_emit_boundary_is_not_cut():
    # entity longer than a chunk but shorter than the overlap
    key = "password = " + "a" * 100
    text = f"start {key} end"
    out = "".join(Redactor(overlap=128).redact_stream(chunked(text, 16)))
    assert out == "start password = [REDACTED] end"


def test_empty_and_tiny_inputs():
    r = Redactor()
    assert "".join(r.redact_stream([])) == ""
    assert "".join(r.redact_stream([""])) == ""
    assert "".join(r.redact_stream(["x"])) == "x"


def test_detect_stream_offsets_are_segment_relative():
    r = Redactor(overlap=16)
    text = "a" * 50 + " bob@x.io " + "b" * 50
    total = 0
    found = []
    for segment, detections in r.detect_stream(chunked(text, 20)):
        for d in detections:
            assert segment[d.start : d.end] == d.text
            found.append((total + d.start, d.text))
        total += len(segment)
    assert found == [(51, "bob@x.io")]


def test_long_entropy_run_up_to_overlap_streams_identically():
    """A high-entropy secret as long as the overlap must stream identically.

    This exercises the WI-1 bound: with the entropy candidate capped at the
    overlap, a run of exactly ``overlap`` characters is one span and is carried
    whole across any chunk boundary, so streaming equals whole-text redaction.
    """
    from safestream_redactor.engine import DEFAULT_OVERLAP

    run = ("Zx9Kq2mVp7Lw3Rt8Yn4Bc6Df1Gh5Jk0" * 300)[:DEFAULT_OVERLAP]
    text = "lead " + run + " tail"
    r = Redactor()  # default overlap
    for chunk_size in (1, 97, 1024, DEFAULT_OVERLAP - 1, DEFAULT_OVERLAP + 3):
        streamed = "".join(r.redact_stream(chunked(text, chunk_size)))
        assert streamed == r.redact(text), f"chunk_size={chunk_size}"


def test_redact_file(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("contact bob@x.io ok\n" * 100)
    r = Redactor(chunk_size=64, overlap=32)
    r.redact_file(src, dst)
    assert dst.read_text() == "contact [REDACTED] ok\n" * 100
