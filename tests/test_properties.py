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
