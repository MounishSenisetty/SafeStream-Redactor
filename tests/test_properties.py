"""Property-based tests for the core invariants.

Two invariants carry the whole design and get generative coverage here:

1. Streaming equivalence — for any input built from bounded-length tokens and
   any chunking, streaming redaction must be byte-identical to whole-text
   redaction (the constant-memory claim is worthless without this).
2. Overlap resolution — the kept detections are sorted, non-overlapping, drawn
   from the input, and maximal (nothing droppable was dropped for no reason).

Examples are derandomized so CI runs are reproducible.
"""

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_redactor import Redactor
from safestream_redactor.entities import Detection, EntityType, resolve_overlaps

# Tokens are bounded (< overlap) so no single entity can exceed the overlap
# window; separators are non-empty and outside every token alphabet so
# adjacent tokens cannot fuse into an unbounded entity.
ENTITY_TOKENS = [
    "jane.doe+x@corp.example.co",
    "123-45-6789",
    "4111 1111 1111 1111",
    "AKIAIOSFODNN7EXAMPLE",
    "10.0.0.1",
    "2001:db8::1",
    "sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12",
    "postgres://svc:S3cret@db.host/app",
    "password: hunter2hunter2hunter2",
]
NOISE_TOKENS = [
    "the",
    "server",
    "restarted",
    "at",
    "order",
    "1234-5678-9012-3456",
    "2024-02-04",
    "v1.2.3.4.5",
    "ratio",
    "12:34:56",
    "ssn:",
    "call",
    "example",
    "naïve",
    "文字",
    "",
]
SEPARATORS = [" ", "\n", "  ", " | ", ", "]

texts = st.lists(st.sampled_from(ENTITY_TOKENS + NOISE_TOKENS), min_size=0, max_size=40).flatmap(
    lambda tokens: st.lists(
        st.sampled_from(SEPARATORS), min_size=len(tokens), max_size=len(tokens)
    ).map(lambda seps: "".join(t + s for t, s in zip(tokens, seps, strict=True)))
)


def chunked(text: str, size: int):
    for i in range(0, len(text), size):
        yield text[i : i + size]


@settings(max_examples=80, derandomize=True, deadline=None)
@given(text=texts, chunk_size=st.integers(min_value=1, max_value=97))
def test_streaming_equals_whole_text_for_any_input_and_chunking(text, chunk_size):
    r = Redactor(overlap=128, load_plugins=False)
    assert "".join(r.redact_stream(chunked(text, chunk_size))) == r.redact(text)


# The longest token above is ~38 chars and the contextual scorer reads a
# 48-char left window (C_left), so any overlap >= 64 clears both L_max(text)
# and C_left — the premise of the streaming-equivalence theorem for this corpus.
# Fuzzing overlap *and* chunk_size together stresses the boundary at every
# combination the theorem must hold for, not just one fixed overlap.
@settings(max_examples=150, derandomize=True, deadline=None)
@given(
    text=texts,
    chunk_size=st.integers(min_value=1, max_value=97),
    overlap=st.integers(min_value=64, max_value=256),
)
def test_streaming_equals_whole_text_across_fuzzed_overlap(text, chunk_size, overlap):
    r = Redactor(overlap=overlap, load_plugins=False)
    assert "".join(r.redact_stream(chunked(text, chunk_size))) == r.redact(text)


# A single entity, deliberately driven across a chunk boundary at *every*
# interior position, must always come out redacted — this is the concrete
# statement of "any entity <= overlap is seen whole regardless of where the
# boundary falls". Each specimen is one non-overlapping entity in plain filler.
BOUNDARY_SPECIMENS = [
    ("email jane.doe@corp.example.com here", "jane.doe@corp.example.com"),
    ("ssn: 123-45-6789 filed", "123-45-6789"),
    ("card 4111 1111 1111 1111 charged", "4111 1111 1111 1111"),
    ("key AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE"),
    ("host 10.20.30.40 up", "10.20.30.40"),
    ("tok ghp_abcdefghijklmnopqrstuvwxyz0123456789 pushed", None),
    ("dsn postgres://svc:S3cretPass@db.internal/app", "S3cretPass"),
]


@given(cut=st.integers(min_value=0, max_value=60))
@settings(max_examples=61, derandomize=True, deadline=None)
def test_single_entity_redacted_at_every_boundary_position(cut):
    r = Redactor(overlap=64, load_plugins=False)
    for text, needle in BOUNDARY_SPECIMENS:
        if cut > len(text):
            continue
        whole = r.redact(text)
        streamed = "".join(r.redact_stream([text[:cut], text[cut:]]))
        assert streamed == whole, f"boundary at {cut} changed output for {text!r}"
        if needle is not None:
            assert needle not in streamed, f"entity leaked with boundary at {cut}"


@settings(max_examples=80, derandomize=True, deadline=None)
@given(text=texts, chunk_size=st.integers(min_value=1, max_value=97))
def test_detect_stream_segments_reassemble_and_offsets_hold(text, chunk_size):
    r = Redactor(overlap=128, load_plugins=False)
    rebuilt = []
    for segment, detections in r.detect_stream(chunked(text, chunk_size)):
        for d in detections:
            assert segment[d.start : d.end] == d.text
        rebuilt.append(segment)
    assert "".join(rebuilt) == text


detections_strategy = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=120),
        st.integers(min_value=1, max_value=25),
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    ).map(
        lambda t: Detection(
            start=t[0],
            end=t[0] + t[1],
            text="x" * t[1],
            entity_type=EntityType.CUSTOM,
            confidence=t[2],
        )
    ),
    max_size=40,
)


@settings(max_examples=200, derandomize=True, deadline=None)
@given(detections=detections_strategy)
def test_resolve_overlaps_invariants(detections):
    kept = resolve_overlaps(detections)
    # sorted and pairwise non-overlapping
    for a, b in itertools.pairwise(kept):
        assert a.start <= b.start
        assert a.end <= b.start
    # drawn from the input, no duplicates
    assert len(kept) == len({id(d) for d in kept})
    assert all(any(d is orig for orig in detections) for d in kept)
    # maximal: anything dropped must overlap something that was kept
    for d in detections:
        assert any(d is k for k in kept) or any(d.overlaps(k) for k in kept)
    # idempotent
    assert resolve_overlaps(kept) == kept
