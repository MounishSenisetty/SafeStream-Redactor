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

from safestream_redactor.entities import Detection, EntityType

DEFAULT_CHUNK_SIZE = 64 * 1024

# Length of the largest entity any built-in detector can produce. The private-key
# block pattern is bounded to an 8 KB body; everything else is far smaller. The
# streaming guarantee is "entities up to ``overlap`` chars are caught even when
# split across chunk boundaries", so ``overlap`` MUST stay above this or such an
# entity could be split and silently missed.
MAX_BUILTIN_ENTITY_LEN = 8 * 1024

# Default overlap comfortably exceeds MAX_BUILTIN_ENTITY_LEN so every built-in
# entity (including a maximal private-key block) is always seen whole. Memory is
# still tiny: chunk_size + overlap per stream.
DEFAULT_OVERLAP = 16 * 1024

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

    # Hard cap on the working buffer. Without it, an entity longer than
    # ``overlap`` — only producible by an unbounded custom regex or a
    # boundary-free high-entropy run — defers emission forever: the emit
    # boundary keeps retreating to the entity's start, the buffer grows without
    # bound (O(n) memory), and every chunk re-detects the whole growing buffer
    # (O(n^2) time). That is a denial-of-service on a tool whose headline claim
    # is constant memory. The cap forces progress once the buffer is large
    # enough that no in-bounds entity could still be pending; see the forced
    # branch below. ``or overlap`` keeps a sane floor when overlap is 0.
    max_buffer = 4 * overlap or 4096
    # Coalesce input before scanning: without this, a producer emitting tiny
    # chunks (e.g. line-buffered ``tail -f``) makes the engine re-detect the
    # whole rolling buffer on every chunk — O(buffer) work per input char. We
    # wait until at least ``scan_step`` new characters beyond ``overlap`` have
    # arrived (or the buffer hits the cap, or input ends) before scanning, which
    # bounds the number of scans to O(n / overlap) regardless of chunk size and
    # does not affect output (larger effective chunks preserve the guarantee).
    scan_step = overlap or 4096

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
    last_scan_len = -1  # buffer length at the previous detection scan
    for chunk in chunks:
        buffer += chunk
        if len(buffer) <= overlap:
            continue
        # Rescan only after ``scan_step`` new characters have arrived since the
        # last scan (unless the cap is reached). This bounds the number of
        # detection passes to O(n / scan_step) even when the buffer sits between
        # overlap and the cap while an over-long entity accumulates — without
        # it, every tiny chunk in that band would re-detect the whole buffer.
        if (
            last_scan_len >= 0
            and len(buffer) - last_scan_len < scan_step
            and len(buffer) < max_buffer
        ):
            continue
        last_scan_len = len(buffer)
        emit_upto = len(buffer) - overlap
        detections = window_detect(prefix, buffer)
        # never cut through a detection: retreat the boundary to its start
        for det in detections:
            if det.start < emit_upto < det.end:
                emit_upto = det.start
        if emit_upto <= 0:
            # An entity starting at buffer position 0 spans the whole emittable
            # region. Detections are non-overlapping, so this is a single
            # entity; ``emit_upto`` can only be 0 here (starts never go
            # negative once dropped by ``window_detect``).
            blocking = [d for d in detections if d.start == 0 and d.end > len(buffer) - overlap]
            complete = [d for d in blocking if d.end < len(buffer)]
            if complete:
                # the entity has terminated within the buffer (a boundary
                # appeared); emit it whole. Nothing else overlaps it, so
                # advancing the boundary to its end cuts nothing.
                emit_upto = max(d.end for d in complete)
            elif len(buffer) < max_buffer:
                continue  # still open and small: accumulate; normal entities resolve here
            else:
                # Over-long entity still open at the cap. Fail closed: redact
                # the whole emittable region (which lies entirely inside the
                # entity) and continue. Such an entity is redacted — possibly as
                # several tokens — rather than silently missed or OOM/hung.
                forced_upto = len(buffer) - overlap
                etype = blocking[0].entity_type if blocking else EntityType.SECRET
                forced = Detection(
                    0, forced_upto, buffer[:forced_upto], etype, 1.0, "streaming-cap"
                )
                yield buffer[:forced_upto], [forced]
                prefix = ""  # left context is meaningless mid-entity; reset
                buffer = buffer[forced_upto:]
                last_scan_len = len(buffer)
                continue
        ready = [d for d in detections if d.end <= emit_upto]
        yield buffer[:emit_upto], ready
        prefix = (prefix + buffer[:emit_upto])[-overlap:] if overlap else ""
        buffer = buffer[emit_upto:]
        last_scan_len = len(buffer)
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
