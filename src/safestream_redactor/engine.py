"""The streaming engine: constant-memory chunked processing with overlap.

How it works
------------

Text arrives in chunks. A rolling buffer holds the current chunk plus a small
tail carried over from the previous iteration. Detection runs on the whole
buffer, but only the part that is at least ``overlap`` characters away from
the buffer's end is emitted; the rest is carried into the next iteration so
an entity that straddles a chunk boundary is always seen whole at least once.

If a detection spans the planned emit boundary, the boundary retreats to the
detection's start so a match is never cut in half. Memory use is therefore
bounded by ``chunk_size + overlap`` (plus the largest single detection),
independent of total input size.

Guarantee: any entity whose text is at most ``overlap`` characters long is
detected even when it is split across chunk boundaries.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

from safestream_redactor.entities import Detection

DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_OVERLAP = 4 * 1024

DetectFn = Callable[[str], list[Detection]]
ApplyFn = Callable[[str, list[Detection]], str]


def read_chunks(
    path: str, chunk_size: int = DEFAULT_CHUNK_SIZE, encoding: str = "utf-8"
) -> Iterator[str]:
    """Yield a file's contents in fixed-size text chunks."""
    with open(path, encoding=encoding, errors="replace") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def stream_windows(
    chunks: Iterable[str],
    detect: DetectFn,
    overlap: int = DEFAULT_OVERLAP,
) -> Iterator[tuple[str, list[Detection]]]:
    """Yield ``(segment, detections)`` pairs covering the input exactly once.

    ``detections`` are the non-overlapping detections fully contained in
    ``segment``, with offsets relative to the segment. ``detect`` must return
    non-overlapping detections (the pipeline guarantees this).
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

    prefix = ""
    buffer = ""
    for chunk in chunks:
        buffer += chunk
        if len(buffer) <= overlap:
            continue
        emit_upto = len(buffer) - overlap
        detections = window_detect(prefix, buffer)
        # never cut through a detection: retreat the boundary to its start
        for det in detections:
            if det.start < emit_upto < det.end:
                emit_upto = det.start
        if emit_upto <= 0:
            continue
        ready = [d for d in detections if d.end <= emit_upto]
        yield buffer[:emit_upto], ready
        prefix = (prefix + buffer[:emit_upto])[-overlap:] if overlap else ""
        buffer = buffer[emit_upto:]
    if buffer:
        yield buffer, window_detect(prefix, buffer)


def stream_transform(
    chunks: Iterable[str],
    detect: DetectFn,
    apply: ApplyFn,
    overlap: int = DEFAULT_OVERLAP,
) -> Iterator[str]:
    """Yield redacted output for an iterable of text chunks, using O(1) memory."""
    for segment, detections in stream_windows(chunks, detect, overlap):
        yield apply(segment, detections)
