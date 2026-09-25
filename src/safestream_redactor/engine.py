"""The streaming engine: constant-memory chunked processing with overlap.

How it works
------------

Text arrives in chunks. A rolling buffer holds the current chunk plus a small
tail carried over from the previous iteration. Detection runs on the whole
buffer, but only the part that is at least ``overlap`` characters away from
the buffer's end is emitted; the rest is carried into the next iteration so
an entity that straddles a chunk boundary is always seen whole at least once.

If a detection spans the planned emit boundary, the boundary retreats to the
detection's start so a match is never cut in half. Small input chunks are coalesced
until a pass can emit at least ``overlap`` characters, so memory use is
bounded by ``max(chunk_size, overlap) + overlap`` plus one chunk (and the
largest single detection), independent of total input size.

Guarantee: any entity whose text is at most ``overlap`` characters long is
detected even when it is split across chunk boundaries.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator

from safestream_redactor.detectors.base import requirements_of
from safestream_redactor.entities import Detection

logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 64 * 1024
# The overlap is the window the engine carries between chunks so an entity split
# by a chunk boundary is still seen whole at least once. Streaming equivalence
# (docs/FORMAL_MODEL.md, Theorem 1) requires ``overlap >= L_max``, the longest
# span any detector can emit. Every pattern bounds its span to at most this
# value (the private-key body and the entropy candidate are the two long ones;
# both are capped to fit), so the default satisfies the theorem's premise
# unconditionally. Keep this in sync with ``MAX_SPAN`` in the detectors.
DEFAULT_OVERLAP = 8 * 1024

DetectFn = Callable[[str], list[Detection]]
ApplyFn = Callable[[str, list[Detection]], str]


def required_overlap(detectors: Iterable[object]) -> int:
    """Smallest overlap that keeps every detector boundary-correct.

    Each detector declares its :class:`~safestream_redactor.detectors.base.StreamingRequirements`
    (or gets a conservative default). The engine's overlap must be at least the
    largest ``required_overlap`` across them so no detector's longest span, plus
    the context it reads, can be cut by a chunk boundary (``docs/FORMAL_MODEL.md``,
    Theorem 1). This replaces the old single global constant with a value the
    engine derives from the detectors actually in use.
    """
    return max((requirements_of(d).required_overlap for d in detectors), default=DEFAULT_OVERLAP)


def read_chunks(
    path: str, chunk_size: int = DEFAULT_CHUNK_SIZE, encoding: str = "utf-8"
) -> Iterator[str]:
    """Yield a file's contents in fixed-size text chunks.

    ``newline=""`` disables universal-newline translation: ``\r\n`` and lone
    ``\r`` reach the detectors and the output exactly as they are in the file,
    so bytes outside redacted spans are preserved (a redactor must not rewrite
    line endings).
    """
    with open(path, encoding=encoding, errors="replace", newline="") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def stream_windows(
    chunks: Iterable[str],
    detect: DetectFn,
    overlap: int = DEFAULT_OVERLAP,
    *,
    initial_context: str = "",
    min_emit: int | None = None,
) -> Iterator[tuple[str, list[Detection]]]:
    """Yield ``(segment, detections)`` pairs covering the input exactly once.

    ``detections`` are the non-overlapping detections fully contained in
    ``segment``, with offsets relative to the segment. ``detect`` must return
    non-overlapping detections (the pipeline guarantees this).

    ``initial_context`` seeds the read-only left context for the very first
    window, as if that text had already been emitted: contextual scoring sees
    it, but detections inside it are dropped and it is never yielded. The
    parallel file engine uses this so a worker starting mid-file scores its
    first characters exactly as the sequential pass would.

    ``min_emit`` is the fewest characters a detection pass should emit; small
    input chunks are coalesced until it is reached. It defaults to ``overlap``
    and is never below it. :class:`~safestream_redactor.redactor.Redactor`
    passes its ``chunk_size`` so any chunking of the input costs the same as
    reading a file in ``chunk_size`` blocks.
    """
    if overlap < 0:
        raise ValueError("overlap must be >= 0")

    def window_detect(prefix: str, buffer: str) -> list[Detection]:
        # ``prefix`` is already-emitted text kept only so detectors (notably
        # the contextual scorer, which looks backward) see the same left
        # context they would in whole-text mode; its detections are dropped.
        shift = len(prefix)
        detections = detect(prefix + buffer)
        kept = []
        for det in detections:
            det.start -= shift
            det.end -= shift
            if det.start >= 0:
                kept.append(det)
        return kept

    prefix = initial_context[-overlap:] if overlap else ""
    buffer = ""
    # Every detection pass rescans ``prefix + buffer`` (up to ``2*overlap`` chars
    # beyond what it emits), so a pass is only worth running once at least
    # ``min_emit`` new characters can be emitted. Without this, a caller feeding
    # small chunks (a line iterator, a socket) triggered a full rescan per chunk:
    # ~100x slower on ~100-char lines. Coalescing bounds the rescan cost per
    # emitted character by a constant, independent of how the input is chunked.
    # Output is unaffected: segmentation is not part of the contract, only the
    # concatenated segments and their detections are.
    min_emit = max(overlap, min_emit or 0, 1)
    need = overlap + min_emit
    pieces: list[str] = []
    buffered = 0
    warned_overlong = False
    for chunk in chunks:
        pieces.append(chunk)
        buffered += len(chunk)
        if buffered < need:
            continue
        buffer = "".join(pieces)
        emit_upto = len(buffer) - overlap
        detections = window_detect(prefix, buffer)
        warned_overlong = _warn_if_overlong(detections, overlap, warned_overlong)
        emit_upto = _retreat_boundary(detections, emit_upto)
        if emit_upto <= 0:
            # a detection pins the whole buffer; wait for another ``min_emit``
            # characters rather than rescanning on every small chunk
            pieces, need = [buffer], buffered + min_emit
            continue
        ready = [d for d in detections if d.end <= emit_upto]
        yield buffer[:emit_upto], ready
        prefix = (prefix + buffer[:emit_upto])[-overlap:] if overlap else ""
        buffer = buffer[emit_upto:]
        pieces, buffered, need = [buffer], len(buffer), overlap + min_emit
    buffer = "".join(pieces)
    if buffer:
        detections = window_detect(prefix, buffer)
        _warn_if_overlong(detections, overlap, warned_overlong)
        yield buffer, detections


def _retreat_boundary(detections: list[Detection], emit_upto: int) -> int:
    """Pull ``emit_upto`` out of every detection that straddles it.

    A boundary that would cut through a detection retreats to that detection's
    start, so a match is never split across two segments. With the
    non-overlapping detections the pipeline guarantees, at most one detection
    straddles the boundary and a single retreat suffices. This iterates to a
    fixpoint so the invariant holds even if a caller (a custom detector, or
    direct use of :func:`stream_windows`) passes *overlapping* detections: a
    retreat can expose a second straddler, and the loop keeps pulling the
    boundary left until no detection crosses it. ``emit_upto`` is strictly
    decreasing and bounded below by 0, so the loop terminates.
    """
    while True:
        moved = emit_upto
        for det in detections:
            if det.start < moved < det.end:
                moved = det.start
        if moved == emit_upto:
            return emit_upto
        emit_upto = moved


def _warn_if_overlong(detections: list[Detection], overlap: int, already: bool) -> bool:
    """Warn once per stream if a detection is longer than the overlap window.

    A span longer than ``overlap`` cannot be guaranteed whole across an
    arbitrary chunk boundary (``docs/FORMAL_MODEL.md``, assumption A1): in
    sequential mode it may be cut, and in parallel mode the seam valve falls
    back. The built-in tiers bound every span to the default overlap, so this
    fires only when a caller shrinks ``overlap`` or a third-party detector emits
    a longer span than it declared — a fail-open coverage risk worth surfacing
    rather than swallowing. Returns the updated "already warned" flag.
    """
    if already or overlap <= 0:
        return already
    for det in detections:
        if det.end - det.start > overlap:
            logger.warning(
                "detection of type %s spans %d characters, longer than the overlap "
                "window (%d); an entity this long that straddles a chunk boundary may "
                "be missed. Raise overlap to at least the longest span you expect.",
                det.entity_type.value,
                det.end - det.start,
                overlap,
            )
            return True
    return already


def stream_transform(
    chunks: Iterable[str],
    detect: DetectFn,
    apply: ApplyFn,
    overlap: int = DEFAULT_OVERLAP,
    *,
    min_emit: int | None = None,
) -> Iterator[str]:
    """Yield redacted output for an iterable of text chunks, using O(1) memory."""
    for segment, detections in stream_windows(chunks, detect, overlap, min_emit=min_emit):
        yield apply(segment, detections)
