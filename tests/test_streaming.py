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


def test_redact_file(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("contact bob@x.io ok\n" * 100)
    r = Redactor(chunk_size=64, overlap=32)
    r.redact_file(src, dst)
    assert dst.read_text() == "contact [REDACTED] ok\n" * 100


def test_large_entity_survives_streaming_at_default_overlap():
    # a private-key block larger than the OLD 4KB overlap must still be redacted
    # when split across chunks — the default overlap now exceeds built-in entities
    body = "MIIEowIBAAKCAQEA" + "A" * 6000
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    text = f"prefix {pem} suffix"
    r = Redactor()  # default overlap
    streamed = "".join(r.redact_stream(chunked(text, 512)))
    assert streamed == r.redact(text)
    assert "[REDACTED]" in streamed and body not in streamed


def test_over_cap_entity_is_redacted_with_bounded_memory():
    # A boundary-free high-entropy token far larger than overlap must not (a) be
    # missed, (b) grow the engine buffer without bound, or (c) hang. Hex tokens
    # are used because they cannot contain a contextual-suppression trigger.
    import hashlib
    import tracemalloc

    r = Redactor()

    def measure(units):
        def gen():
            yield "k "
            for i in range(units):
                yield hashlib.sha256(str(i).encode()).hexdigest()  # 64 hex chars, no boundary
            yield " z\n"

        tracemalloc.start()
        redacted = False
        for piece in r.redact_stream(gen()):  # consume + discard: measure engine only
            redacted = redacted or "[REDACTED]" in piece
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak, redacted

    small_peak, red_small = measure(2000)  # ~128 KB token
    big_peak, red_big = measure(8000)  # ~512 KB token (4x larger)
    assert red_small and red_big  # the over-long secret is redacted, never leaked
    # 4x the input, roughly the same peak: memory is bounded by the cap, not O(n)
    assert big_peak < 2 * small_peak


def test_complete_entity_larger_than_overlap_streams_identically():
    # an entity longer than overlap but that terminates within a few overlaps is
    # emitted whole, identically to non-streaming redaction
    import hashlib

    r = Redactor()
    token = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(500))  # ~32 KB
    assert r.overlap < len(token) < 4 * r.overlap
    text = f"k {token} z"
    for n in (37, 4096, 65536):
        assert "".join(r.redact_stream(chunked(text, n))) == r.redact(text)


def test_small_overlap_warns_at_construction(caplog):
    with caplog.at_level("WARNING", logger="safestream_redactor.redactor"):
        Redactor(overlap=1024)
    assert any("below the largest built-in entity size" in r.getMessage() for r in caplog.records)


def test_oversized_detection_warns_once(caplog):
    long_word = "Z" * 200
    r = Redactor(custom_words=[long_word], overlap=100)
    caplog.clear()
    with caplog.at_level("WARNING", logger="safestream_redactor.redactor"):
        r.detect(f"secret {long_word} here")
        r.detect(f"again {long_word} here")
    oversized = [rec for rec in caplog.records if "longer than overlap" in rec.getMessage()]
    assert len(oversized) == 1  # warn-once
