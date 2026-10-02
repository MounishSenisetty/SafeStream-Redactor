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
    r = Redactor(overlap=128, load_plugins=False, allow_unsafe_overlap=True)
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
    r = Redactor(overlap=overlap, load_plugins=False, allow_unsafe_overlap=True)
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
    r = Redactor(overlap=64, load_plugins=False, allow_unsafe_overlap=True)
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
    r = Redactor(overlap=128, load_plugins=False, allow_unsafe_overlap=True)
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


def test_ner_overlap_never_leaks_tier0_characters():
    """A PERSON tag inside an email must not shrink the email's redaction."""
    text = "mail john.doe@example.com now"
    email = Detection(5, 25, "john.doe@example.com", EntityType.EMAIL, 0.95)
    person = Detection(5, 13, "john.doe", EntityType.PERSON, 0.99, source="onnx")
    for dets in ([email, person], [person, email]):
        assert resolve_overlaps(dets) == [email]
    redactor = Redactor(extra_detectors=[_Fixed([person])])
    assert [(d.text, d.entity_type) for d in redactor.detect(text)] == [
        ("john.doe@example.com", EntityType.EMAIL)
    ]
    assert redactor.redact(text) == "mail [REDACTED] now"

    # an NER span sticking out of a Tier-0 span widens it; the Tier-0 label wins
    person = Detection(0, 13, "mail john.doe", EntityType.PERSON, 0.99, source="onnx")
    (got,) = resolve_overlaps([email, person])
    assert (got.start, got.end, got.entity_type) == (0, 25, EntityType.EMAIL)
    assert got.text == text[0:25]


class _Fixed:
    """A stand-in NER tier that returns canned detections."""

    name = "onnx"

    def __init__(self, dets: list[Detection]) -> None:
        self._dets = dets

    def detect(self, text: str) -> list[Detection]:
        return [Detection(d.start, d.end, d.text, d.entity_type, d.confidence, d.source)
                for d in self._dets]  # fmt: skip


@settings(max_examples=300, derandomize=True, deadline=None)
@given(
    spans=st.lists(
        st.tuples(st.integers(0, 80), st.integers(1, 20), st.booleans(), st.floats(0, 1)),
        max_size=30,
    )
)
def test_mixed_tier_resolution_covers_every_tier0_character(spans):
    text = "".join(chr(97 + i % 26) for i in range(120))
    dets = [
        Detection(s, s + n, text[s : s + n], EntityType.CUSTOM, c, "onnx" if ner else "custom")
        for s, n, ner, c in spans
    ]
    kept = resolve_overlaps(dets)
    for a, b in itertools.pairwise(kept):
        assert a.end <= b.start
    assert all(k.text == text[k.start : k.end] for k in kept)
    covered = {i for k in kept for i in range(k.start, k.end)}
    # every character the Tier-0-only resolution would redact is still redacted
    tier0 = resolve_overlaps([d for d in dets if d.source == "custom"])
    assert {i for k in tier0 for i in range(k.start, k.end)} <= covered


def test_resolve_overlaps_tiebreak_is_deterministic():
    """Equal-confidence overlaps resolve by longer span, then earlier start.

    Pins the arbitration order so a future sort-key change can't silently
    reorder ties — the case a calibrator can produce when it maps two tiers'
    detections to the same probability (R-ARB-3).
    """
    # same confidence, overlapping: the longer span must win
    short = Detection(0, 4, "xxxx", EntityType.PHONE, 0.9)
    long = Detection(0, 8, "xxxxxxxx", EntityType.CREDIT_CARD, 0.9)
    assert resolve_overlaps([short, long]) == [long]
    assert resolve_overlaps([long, short]) == [long]  # input order irrelevant

    # equal confidence and equal length, overlapping: earlier start wins
    left = Detection(0, 5, "aaaaa", EntityType.CUSTOM, 0.7)
    right = Detection(2, 7, "bbbbb", EntityType.CUSTOM, 0.7)
    assert resolve_overlaps([right, left]) == [left]
    assert resolve_overlaps([left, right]) == [left]


@settings(max_examples=200, derandomize=True, deadline=None)
@given(
    text=st.text(alphabet="ab\n\r", max_size=60),
    cuts=st.lists(st.integers(min_value=0, max_value=60), max_size=6),
    picks=st.lists(st.integers(min_value=0, max_value=60), max_size=8),
)
def test_line_tracker_matches_naive_positions(text, cuts, picks):
    # For any text, any segmentation, and any sorted offsets, the streaming
    # (line, column) must equal the one computed over the whole text at once.
    from safestream_redactor.locate import LineTracker

    bounds = sorted({0, len(text), *(c for c in cuts if c <= len(text))})
    offsets = sorted({p for p in picks if p < len(text)})
    tracker = LineTracker()
    got = []
    for seg_start, seg_end in itertools.pairwise(bounds):
        segment = text[seg_start:seg_end]
        for off in offsets:
            if seg_start <= off < seg_end:
                got.append(tracker.locate(segment, seg_start, off))
        tracker.finish(segment, seg_start)
    naive = [(text.count("\n", 0, o) + 1, o - (text.rfind("\n", 0, o) + 1) + 1) for o in offsets]
    assert got == naive


@settings(max_examples=200, derandomize=True, deadline=None)
@given(value=st.text(min_size=1, max_size=30), keep=st.integers(min_value=-2, max_value=40))
def test_mask_never_reveals_more_than_half(value, keep):
    from safestream_redactor.policy import RedactionPolicy

    det = Detection(0, len(value), value, EntityType.CUSTOM, 1.0)
    out = RedactionPolicy(mode="mask", mask_keep_last=keep).render(det)
    assert len(out) == len(value)  # shape preserved
    visible = min(max(0, keep), len(value) // 2)
    assert out == "*" * (len(value) - visible) + value[len(value) - visible :]
