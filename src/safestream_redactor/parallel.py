"""Parallel redaction of a single large file across CPU cores.

Design (see docs/adr/0001-intra-file-parallelism.md for the full rationale)
---------------------------------------------------------------------------

The file is split into byte ranges aligned to character boundaries. Each
worker redacts its range with the ordinary streaming engine, extended on both
sides so the seams are invisible:

- an ``overlap``-sized *scanned pad* on each side of the range, so a worker
  sees every detection that crosses its seams in full;
- a further ``overlap`` of *context-only* prefix, so the first scanned
  character has the same left context the sequential pass would give it.

Seam protocol: a detection that crosses a seam (starts before it, ends after
it) is called a *straddler* and belongs to the **left** worker — the left
worker renders its replacement and consumes the straddled characters, and the
right worker starts emitting at the straddler's end. Both neighbours compute
the straddler independently from the same bytes and report it; the
orchestrator verifies both sides agreed (the *seam valve*). If any seam
disagrees — only possible for inputs outside the engine's documented
guarantees, e.g. an entity longer than ``overlap`` sitting exactly on a seam —
the parts are discarded and the file is redacted sequentially instead. The
valve makes character loss or duplication at a seam structurally impossible:
parallel mode either produces output byte-identical to the sequential pass or
falls back to the sequential pass itself.

Memory per worker stays bounded by the streaming engine's buffer plus a
``2*overlap`` holdback, so the constant-memory property is preserved
(total memory scales with worker count, never with file size).

Only self-synchronising encodings can be split safely: UTF-8 (align by
skipping continuation bytes) and single-byte codecs (any split is safe).
Other encodings fall back to the sequential path.
"""

from __future__ import annotations

import codecs
import contextlib
import io
import itertools
import logging
import os
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING

from safestream_redactor.entities import Detection
from safestream_redactor.report import RedactionStats

if TYPE_CHECKING:
    from safestream_redactor.redactor import Redactor

logger = logging.getLogger(__name__)

# A range must dwarf the overlap for the seam math to hold (a range shorter
# than 2*overlap could put both seams inside one detection's reach) and for
# worker startup to amortise. 8 MB ranges keep peak detections-in-flight small
# while giving each worker seconds of work at measured throughput.
MIN_RANGE_BYTES = 8 * 1024 * 1024

_SINGLE_BYTE_CODECS = frozenset(
    {"ascii", "latin-1", "iso8859-1", "cp1252", "cp1251", "cp437", "koi8-r"}
)


def _codec_name(encoding: str) -> str:
    return codecs.lookup(encoding).name


def splittable_encoding(encoding: str) -> bool:
    """True if a file in this encoding can be split at byte offsets safely."""
    try:
        name = _codec_name(encoding)
    except LookupError:
        return False
    return name == "utf-8" or name in _SINGLE_BYTE_CODECS


@dataclass(frozen=True, slots=True)
class SeamReport:
    """What one worker concluded about one seam, for cross-checking.

    ``rel_start``/``rel_end`` are the straddling detection's offsets relative
    to the seam's character position (or ``None`` when no detection crossed).
    Both neighbours of a seam must produce equal reports or the run falls back.
    """

    rel_start: int | None = None
    rel_end: int | None = None
    entity_type: str | None = None


@dataclass(slots=True)
class _RangeResult:
    index: int
    part_path: str
    stats: RedactionStats
    start_seam: SeamReport  # what this worker assumed about its left seam
    end_seam: SeamReport  # what this worker decided about its right seam


def _align_utf8(f: IO[bytes], offset: int, size: int) -> int:
    """Advance ``offset`` to the next UTF-8 character start (or EOF)."""
    if offset <= 0:
        return 0
    if offset >= size:
        return size
    f.seek(offset)
    probe = f.read(4)
    for i, b in enumerate(probe):
        if not 0x80 <= b < 0xC0:  # not a continuation byte
            return offset + i
    return min(offset + len(probe), size)


def _align(f: IO[bytes], offset: int, size: int, utf8: bool) -> int:
    """A split point that neither cuts a character nor a ``\\r\\n`` pair.

    The sequential reader collapses ``\\r\\n`` to ``\\n`` (universal newlines);
    splitting between the two bytes would make each half decode to its own
    ``\\n`` and desynchronise the parallel text from the sequential text, so
    such a point is nudged past the ``\\n``. Both bytes are unambiguous in
    UTF-8 and in every allowed single-byte codec.
    """
    if utf8:
        offset = _align_utf8(f, offset, size)
    if 0 < offset < size:
        f.seek(offset - 1)
        if f.read(2) == b"\r\n":
            offset += 1
    return min(offset, size)


def _split_points(path: str, n_ranges: int, encoding: str) -> list[int]:
    """Byte offsets ``[0, ..., size]`` splitting ``path`` into aligned ranges."""
    size = os.path.getsize(path)
    raw = [size * i // n_ranges for i in range(n_ranges + 1)]
    utf8 = _codec_name(encoding) == "utf-8"
    with open(path, "rb") as f:
        aligned = [0] + [_align(f, off, size, utf8) for off in raw[1:-1]] + [size]
    return sorted(set(aligned))


def _decode_bytes(
    path: str, start: int, end: int, encoding: str, chunk_bytes: int
) -> Iterator[str]:
    """Decode bytes ``[start, end)`` of ``path`` as a stream of text chunks.

    Uses the same incremental decoder (``errors="replace"``) plus the same
    universal-newline translation the sequential text reader applies, so for
    ranges aligned by :func:`_align` the decoded text is exactly the
    sequential pass's substring.
    """
    decoder = io.IncrementalNewlineDecoder(
        codecs.getincrementaldecoder(encoding)(errors="replace"), translate=True
    )
    with open(path, "rb") as f:
        f.seek(start)
        remaining = end - start
        while remaining > 0:
            data = f.read(min(chunk_bytes, remaining))
            if not data:
                break
            remaining -= len(data)
            text = decoder.decode(data)
            if text:
                yield text
        tail = decoder.decode(b"", True)
        if tail:
            yield tail


def _read_chars_before(path: str, offset: int, n_chars: int, encoding: str) -> str:
    """The last ``n_chars`` characters of the text that ends at byte ``offset``."""
    if offset <= 0 or n_chars <= 0:
        return ""
    # 4 bytes/char upper bound for UTF-8; exact for single-byte codecs
    start = max(0, offset - 4 * n_chars - 4)
    if _codec_name(encoding) == "utf-8":
        with open(path, "rb") as f:
            start = _align_utf8(f, start, offset)
    text = "".join(_decode_bytes(path, start, offset, encoding, 1 << 16))
    return text[-n_chars:]


def _read_chars_after(path: str, offset: int, n_chars: int, encoding: str) -> str:
    """Up to the first ``n_chars`` characters of the text starting at byte ``offset``."""
    if n_chars <= 0:
        return ""
    size = os.path.getsize(path)
    end = min(size, offset + 4 * n_chars + 4)
    out: list[str] = []
    have = 0
    for piece in _decode_bytes(path, offset, end, encoding, 1 << 16):
        out.append(piece)
        have += len(piece)
        if have >= n_chars:
            break
    return "".join(out)[:n_chars]


@dataclass(slots=True)
class _Job:
    input_path: str
    part_path: str
    byte_start: int
    byte_end: int
    index: int
    is_first: bool
    is_last: bool


# --- worker-process globals (mirrors scheduler.py) --------------------------

_WORKER_REDACTOR: Redactor | None = None
_WORKER_ENCODING = "utf-8"


def _init_worker(redactor: Redactor, encoding: str, offline_guard: bool) -> None:
    global _WORKER_REDACTOR, _WORKER_ENCODING
    if offline_guard:
        from safestream_redactor import netguard

        netguard.install()
    _WORKER_REDACTOR = redactor
    _WORKER_ENCODING = encoding


def _find_straddler(detections: list[tuple[int, Detection]], seam: int) -> SeamReport:
    """The (at most one) detection crossing character position ``seam``."""
    for abs_start, det in detections:
        abs_end = abs_start + (det.end - det.start)
        if abs_start < seam < abs_end:
            return SeamReport(abs_start - seam, abs_end - seam, det.entity_type.value)
    return SeamReport()


def _redact_range(job: _Job) -> _RangeResult:
    assert _WORKER_REDACTOR is not None
    redactor, encoding = _WORKER_REDACTOR, _WORKER_ENCODING
    ov = redactor.overlap
    from safestream_redactor.engine import stream_windows

    # Left of the range: `ov` chars scanned (to see start-seam straddlers in
    # full) preceded by `ov` chars of context-only prefix. First range: none.
    if job.is_first:
        left_pad = ""
        context = ""
    else:
        both = _read_chars_before(job.input_path, job.byte_start, 2 * ov, encoding)
        left_pad, context = both[-ov:], both[:-ov]
    seam_start = len(left_pad)  # local char position of the range's first char

    range_chars = 0

    def feed() -> Iterator[str]:
        nonlocal range_chars
        if left_pad:
            yield left_pad
        for piece in _decode_bytes(
            job.input_path, job.byte_start, job.byte_end, encoding, redactor.chunk_size
        ):
            range_chars += len(piece)
            yield piece
        if not job.is_last:
            right_pad = _read_chars_after(job.input_path, job.byte_end, ov, encoding)
            if right_pad:
                yield right_pad

    stats = RedactionStats()
    # (absolute local char start, segment text, [(abs det start, det), ...])
    pending: list[tuple[int, str, list[tuple[int, Detection]]]] = []
    all_dets: list[tuple[int, Detection]] = []  # kept only within 2*ov of the head
    cursor = 0
    start_cut: int | None = 0 if job.is_first else None
    start_report = SeamReport()

    def flush(upto: int, end_cut: int | None = None) -> None:
        """Write pending segments whose text lies entirely below ``upto``."""
        assert start_cut is not None
        while pending and (pending[0][0] + len(pending[0][1]) <= upto or end_cut is not None):
            seg_start, text, dets = pending.pop(0)
            seg_end = seg_start + len(text)
            lo = max(seg_start, start_cut)
            hi = seg_end if end_cut is None else min(seg_end, end_cut)
            if hi <= lo:
                continue
            piece = text[lo - seg_start : hi - seg_start]
            kept: list[Detection] = []
            for abs_start, det in dets:
                abs_end = abs_start + (det.end - det.start)
                if abs_start >= lo and abs_end <= hi:
                    det.start = abs_start - lo
                    det.end = abs_end - lo
                    kept.append(det)
                    stats.counts[det.entity_type.value] += 1
            redacted = redactor.policy.apply(piece, kept)
            stats.chars_in += len(piece)
            stats.chars_out += len(redacted)
            stats.decode_replacements += piece.count("�")
            out.write(redacted)

    fd, tmp_part = tempfile.mkstemp(
        dir=os.path.dirname(job.part_path) or ".",
        prefix=os.path.basename(job.part_path) + ".",
    )
    try:
        with open(fd, "w", encoding=encoding) as out:
            for segment, detections in stream_windows(
                feed(), redactor.detect, ov, initial_context=context
            ):
                abs_dets = [(cursor + d.start, d) for d in detections]
                pending.append((cursor, segment, abs_dets))
                all_dets.extend(abs_dets)
                cursor += len(segment)
                # decide the start cut once every start-seam straddler must
                # have been seen (they end within `ov` past the seam)
                if start_cut is None and cursor >= seam_start + 2 * ov:
                    start_report = _find_straddler(all_dets, seam_start)
                    start_cut = (
                        seam_start + start_report.rel_end
                        if start_report.rel_end is not None
                        else seam_start
                    )
                if start_cut is not None:
                    # anything older than 2*ov behind the head can no longer be
                    # affected by the (still unknown) end seam
                    flush(cursor - 2 * ov)
                    all_dets = [
                        (s, d) for s, d in all_dets if s + (d.end - d.start) > cursor - 2 * ov
                    ]

            seam_end = seam_start + range_chars
            if start_cut is None:  # tiny stream: decide now from everything seen
                start_report = _find_straddler(all_dets, seam_start)
                start_cut = (
                    seam_start + start_report.rel_end
                    if start_report.rel_end is not None
                    else seam_start
                )
            if job.is_last:
                end_report = SeamReport()
                end_cut = seam_end
            else:
                end_report = _find_straddler(all_dets, seam_end)
                end_cut = (
                    seam_end + end_report.rel_end if end_report.rel_end is not None else seam_end
                )
            flush(cursor, end_cut=end_cut)
        os.replace(tmp_part, job.part_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_part)
        raise
    return _RangeResult(job.index, job.part_path, stats, start_report, end_report)


@dataclass(slots=True)
class ParallelOutcome:
    """What :func:`redact_file_parallel` did, for tests and observability."""

    stats: RedactionStats
    ranges: int = 1
    fell_back: bool = False
    fallback_reason: str | None = None


def plan_ranges(path: str, workers: int, encoding: str, overlap: int) -> list[int]:
    """Split points for ``path``, honouring alignment and minimum range size."""
    size = os.path.getsize(path)
    n = min(workers, max(1, size // MIN_RANGE_BYTES))
    if n < 2:
        return [0, size]
    points = _split_points(path, n, encoding)
    # A range must hold both its seam neighbourhoods without them colliding: the
    # start seam is decided after 2*overlap of scanning and the end seam needs a
    # further 2*overlap of look-ahead, so 4*overlap is the floor. Below it, split
    # coarser rather than risk a range whose two seams overlap.
    while len(points) > 2 and any(b - a < 4 * overlap for a, b in itertools.pairwise(points)):
        n -= 1
        if n < 2:
            return [0, size]
        points = _split_points(path, n, encoding)
    return points


def redact_file_parallel(
    redactor: Redactor,
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    workers: int,
    encoding: str = "utf-8",
    offline_guard: bool = False,
) -> ParallelOutcome:
    """Redact one file using up to ``workers`` processes.

    Output is byte-identical to :meth:`Redactor.redact_file` for inputs within
    the engine's documented guarantees (entities no longer than ``overlap``);
    when a seam cross-check fails outside those guarantees, the whole file is
    transparently redacted sequentially instead. Falls back to the sequential
    path outright for small files, non-splittable encodings, or ``workers=1``.

    ``offline_guard`` installs the network guard in worker processes (the
    caller's process is never patched).
    """
    from concurrent.futures import ProcessPoolExecutor

    in_path, out_path = os.fspath(input_path), os.fspath(output_path)

    def sequential(reason: str | None) -> ParallelOutcome:
        stats = redactor.redact_file(in_path, out_path, encoding=encoding)
        return ParallelOutcome(
            stats, ranges=1, fell_back=reason is not None, fallback_reason=reason
        )

    if workers <= 1:
        return sequential(None)
    if not splittable_encoding(encoding):
        logger.info("encoding %r cannot be split safely; redacting sequentially", encoding)
        return sequential("encoding")
    points = plan_ranges(in_path, workers, encoding, redactor.overlap)
    if len(points) < 3:
        return sequential(None)  # too small to be worth splitting: not a fallback

    # same self-overwrite guard as the sequential path
    if os.path.exists(out_path):
        with contextlib.suppress(OSError):
            if os.path.samefile(in_path, out_path):
                raise ValueError(
                    f"input and output refer to the same file ({out_path!r}); "
                    "write to a different path, then move it into place"
                )

    n_ranges = len(points) - 1
    part_dir = tempfile.mkdtemp(
        dir=os.path.dirname(out_path) or ".", prefix=os.path.basename(out_path) + ".parts."
    )
    try:
        jobs = [
            _Job(
                input_path=in_path,
                part_path=os.path.join(part_dir, f"part{i:05d}"),
                byte_start=points[i],
                byte_end=points[i + 1],
                index=i,
                is_first=i == 0,
                is_last=i == n_ranges - 1,
            )
            for i in range(n_ranges)
        ]
        with ProcessPoolExecutor(
            max_workers=min(workers, n_ranges),
            initializer=_init_worker,
            initargs=(redactor, encoding, offline_guard),
        ) as pool:
            results = sorted(pool.map(_redact_range, jobs), key=lambda r: r.index)

        # the seam valve: both neighbours must have reached the same
        # conclusion about every seam, or characters could be lost/duplicated
        for left, right in itertools.pairwise(results):
            if left.end_seam != right.start_seam:
                logger.warning(
                    "seam disagreement between ranges %d and %d (%r vs %r); "
                    "redacting sequentially instead",
                    left.index,
                    right.index,
                    left.end_seam,
                    right.start_seam,
                )
                return sequential("seam")

        stats = RedactionStats()
        fd, tmp_out = tempfile.mkstemp(
            dir=os.path.dirname(out_path) or ".", prefix=os.path.basename(out_path) + "."
        )
        try:
            with open(fd, "wb") as out:
                for res in results:
                    with open(res.part_path, "rb") as part:
                        shutil.copyfileobj(part, out, 1 << 20)
                    stats.merge(res.stats)
            from safestream_redactor.redactor import _match_destination_mode

            _match_destination_mode(tmp_out, out_path)
            os.replace(tmp_out, out_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_out)
            raise
        return ParallelOutcome(stats, ranges=n_ranges)
    finally:
        shutil.rmtree(part_dir, ignore_errors=True)
