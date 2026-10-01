"""Framework-free logic behind the web UI.

Everything the Streamlit page needs that is not drawing widgets lives here:
turning sidebar settings into a :class:`~safestream_redactor.redactor.Redactor`,
guarding uploads, scanning, and rendering highlighted HTML. None of it imports
Streamlit, so it is tested by the ordinary test suite without the ``ui`` extra,
and the page itself (``app.py``) stays a thin layer of widgets over it.

The UI adds no detection or redaction logic of its own. Findings come from
``Redactor.detect_stream`` (the streaming path the CLI uses, honouring the
chosen chunk size) and replacements from ``RedactionPolicy.render``, so what
the page shows is exactly what ``safestream redact`` would write.
"""

from __future__ import annotations

import atexit
import html
import ipaddress
import os
import shutil
import tempfile
import time
from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP, WindowTrace
from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.locate import LineTracker
from safestream_redactor.policy import RedactionMode, RedactionPolicy
from safestream_redactor.redactor import Redactor
from safestream_redactor.report import RedactionStats
from safestream_redactor.severity import CRITICAL, HIGH, LOW, MEDIUM, severity_for

_MIB = 1024 * 1024
# Pasted text, and uploads up to this size, are analysed in the page: held in
# memory, fully highlighted, and diffed. Larger uploads take the large-file path
# (spooled to disk, redacted by the streaming engine on every core, previewed).
MAX_INPUT_BYTES = 5 * _MIB
# Upload cap (Streamlit's --server.maxUploadSize). Streamlit keeps an upload in
# RAM while it is selected, so this also bounds the page's memory use.
DEFAULT_MAX_UPLOAD_MB = 2048
# Large-file outputs up to this size are also offered as a browser download
# (which Streamlit serves from memory); every size can be saved to a folder.
DOWNLOAD_LIMIT_BYTES = 200 * _MIB
# Single-core throughput measured on mixed logs; only used for a rough estimate.
_BYTES_PER_SECOND_PER_CORE = 1.2e6
# The annotated views render at most this many characters; findings, counts, and
# the redacted output always cover the whole input.
PREVIEW_CHARS = 200_000
UPLOAD_TYPES = ("txt", "log", "json", "csv")
# Bytes sniffed to recognise a binary upload (a NUL byte, the heuristic git uses).
_BINARY_SNIFF = 8192

# Entity types the regex/validator tier filters on. PERSON/ORG/LOC come only from
# the name tiers (toggled separately) and CUSTOM only from the user's own rules.
PATTERN_TYPES: tuple[str, ...] = tuple(
    t.value
    for t in EntityType
    if t not in (EntityType.PERSON, EntityType.ORG, EntityType.LOC, EntityType.CUSTOM)
)

# Translucent fills read on both light and dark themes.
SEVERITY_COLORS = {
    CRITICAL: "rgba(220, 38, 38, 0.35)",
    HIGH: "rgba(234, 88, 12, 0.35)",
    MEDIUM: "rgba(202, 138, 4, 0.35)",
    LOW: "rgba(37, 99, 235, 0.30)",
}
_REPLACEMENT_COLOR = "rgba(22, 163, 74, 0.30)"


class RedactStyle(str, Enum):
    """How the Redact mode rewrites a finding."""

    REPLACE = "replace"  # a fixed token such as [REDACTED]
    MASK = "mask"  # **********6789 (at most half the value stays visible)
    HASH = "hash"  # a keyed HMAC pseudonym, stable for equal values


class SettingsError(ValueError):
    """The chosen settings cannot build a redactor. The message is user-facing."""


class InputError(ValueError):
    """The input cannot be processed (too large, binary). The message is user-facing."""


@dataclass(frozen=True, slots=True)
class Settings:
    """Everything the sidebar controls.

    ``types=None`` runs every pattern type; an empty tuple runs none of them (only
    custom rules and the name tiers), which is what deselecting them all means.
    """

    min_confidence: float = 0.5
    chunk_size: int = DEFAULT_CHUNK_SIZE
    overlap: int = DEFAULT_OVERLAP
    types: tuple[str, ...] | None = None
    use_entropy: bool = True
    use_names: bool = False
    use_ner: bool = False
    custom_words: tuple[str, ...] = ()
    custom_patterns: tuple[str, ...] = ()
    style: RedactStyle = RedactStyle.REPLACE
    replacement: str = "[REDACTED]"
    keep_last: int = 4
    hash_key: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """One detection, located in the input and paired with its replacement."""

    entity_type: str
    severity: str
    start: int
    end: int
    line: int
    column: int
    confidence: float
    source: str
    text: str
    replacement: str


@dataclass(frozen=True, slots=True)
class DecodedInput:
    text: str
    # U+FFFD characters produced by decoding: bytes that were not valid UTF-8
    # and therefore were never scanned (the CLI warns about the same thing).
    replaced_bytes: int = 0


@dataclass(frozen=True, slots=True)
class PrivacyStatus:
    local_only: bool
    issues: tuple[str, ...] = field(default_factory=tuple)


def parse_rules(block: str) -> tuple[str, ...]:
    """One rule per line; blank lines and ``#`` comments are ignored, order kept."""
    rules: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and line not in rules:
            rules.append(line)
    return tuple(rules)


def build_redactor(settings: Settings) -> Redactor:
    """Build the redactor for ``settings``, or raise :class:`SettingsError`.

    Validation is the core engine's own (chunk size, overlap safety, confidence
    range, regex syntax, policy options); this only rephrases it for a person
    looking at a form rather than a traceback.
    """
    if settings.style is RedactStyle.HASH and not settings.hash_key:
        raise SettingsError("Hash mode needs a secret key: the pseudonyms are keyed HMACs.")
    mode = {
        RedactStyle.REPLACE: RedactionMode.REPLACE,
        RedactStyle.MASK: RedactionMode.MASK,
        RedactStyle.HASH: RedactionMode.PSEUDONYMIZE,
    }[settings.style]
    try:
        policy = RedactionPolicy(
            mode=mode,
            replacement=settings.replacement,
            mask_keep_last=settings.keep_last,
            hmac_key=settings.hash_key or None,
        )
        return Redactor(
            types=None if settings.types is None else list(settings.types),
            policy=policy,
            min_confidence=settings.min_confidence,
            custom_words=settings.custom_words,
            custom_patterns=settings.custom_patterns,
            use_ner=settings.use_ner,
            use_gazetteer=settings.use_names,
            use_ensemble=settings.use_names,
            use_entropy=settings.use_entropy,
            chunk_size=settings.chunk_size,
            overlap=settings.overlap,
        )
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc
    except (ImportError, OSError) as exc:
        # spaCy (or its model) missing: the only optional dependency reachable here
        raise SettingsError(
            f"The NER tier is unavailable ({exc}). Install it with "
            "pip install 'safestream-redactor[ner]' and download a model, or turn it off."
        ) from exc


def check_text_size(text: str, max_bytes: int = MAX_INPUT_BYTES) -> None:
    """Reject pasted text the playground would have to hold beyond its cap."""
    # UTF-8 needs at most 4 bytes per character: skip the encode when that bound
    # already fits, so the common case costs nothing.
    if len(text) * 4 > max_bytes and len(text.encode("utf-8")) > max_bytes:
        raise InputError(_too_large(max_bytes))


def decode_upload(data: bytes, max_bytes: int = MAX_INPUT_BYTES) -> DecodedInput:
    """Decode an uploaded file as UTF-8, refusing oversized and binary files."""
    if len(data) > max_bytes:
        raise InputError(_too_large(max_bytes))
    if b"\0" in data[:_BINARY_SNIFF]:
        raise InputError("This looks like a binary file. Upload text (.txt, .log, .json, .csv).")
    # utf-8-sig drops a BOM so it can't shift the first line's columns
    text = data.decode("utf-8-sig", errors="replace")
    return DecodedInput(text, text.count("�") - data.count("�".encode()))


def _too_large(max_bytes: int) -> str:
    return (
        f"Input is larger than the {max_bytes // _MIB} MiB limit for text analysed in the "
        "page. Upload it as a file instead (large files are streamed), or use the CLI: "
        "safestream redact BIG.log -o CLEAN.log"
    )


def _chunks(text: str, size: int) -> Iterator[str]:
    for i in range(0, len(text), size):
        yield text[i : i + size]


def scan(redactor: Redactor, text: str) -> list[Finding]:
    """Every finding in ``text``, in order, via the streaming engine.

    The text is fed through ``detect_stream`` in ``chunk_size`` pieces (exactly
    like a file on the CLI), so the chunking settings are exercised for real.
    """
    findings: list[Finding] = []
    tracker = LineTracker()
    offset = 0
    for segment, detections in redactor.detect_stream(_chunks(text, redactor.chunk_size)):
        for det in detections:
            start, end = offset + det.start, offset + det.end
            line, column = tracker.locate(segment, offset, start)
            findings.append(_finding(redactor, det, start, end, line, column))
        tracker.finish(segment, offset)
        offset += len(segment)
    return findings


def _finding(
    redactor: Redactor, det: Detection, start: int, end: int, line: int, column: int
) -> Finding:
    return Finding(
        entity_type=det.entity_type.value,
        severity=severity_for(det.entity_type),
        start=start,
        end=end,
        line=line,
        column=column,
        confidence=det.confidence,
        source=det.source,
        text=det.text,
        replacement=redactor.policy.render(det),
    )


def redact_text(text: str, findings: Iterable[Finding]) -> str:
    """``text`` with every finding replaced (identical to ``Redactor.redact``)."""
    parts: list[str] = []
    cursor = 0
    for f in findings:
        parts.append(text[cursor : f.start])
        parts.append(f.replacement)
        cursor = f.end
    parts.append(text[cursor:])
    return "".join(parts)


def highlight_html(
    text: str,
    findings: list[Finding],
    *,
    redacted: bool = False,
    limit: int = PREVIEW_CHARS,
) -> str:
    """Escaped HTML of ``text`` with findings wrapped in coloured ``<mark>`` tags.

    With ``redacted=True`` each finding is shown as its replacement instead of
    the original value. Every piece of input is HTML-escaped (the input is
    untrusted: an uploaded file may well contain markup). Only the first
    ``limit`` characters are rendered; the caller says so when that truncates.
    """
    out = ['<pre class="ss-view">']
    cursor = 0
    for f in findings:
        if f.start >= limit:
            break
        out.append(html.escape(text[cursor : f.start]))
        tip = f"{f.entity_type} · {f.severity} · {f.confidence:.2f} · line {f.line}:{f.column}"
        color = _REPLACEMENT_COLOR if redacted else SEVERITY_COLORS[f.severity]
        body = f.replacement if redacted else text[f.start : f.end]
        out.append(
            f'<mark style="background:{color}" title="{html.escape(tip)}">'
            f"{html.escape(body)}</mark>"
        )
        cursor = f.end
    if cursor < limit:
        out.append(html.escape(text[cursor:limit]))
    out.append("</pre>")
    return "".join(out)


def finding_rows(findings: Iterable[Finding], *, reveal: bool = False) -> list[dict[str, object]]:
    """Table rows for the findings view. Matched values are hidden unless ``reveal``."""
    return [
        {
            "Type": f.entity_type,
            "Severity": f.severity,
            "Confidence": round(f.confidence, 2),
            "Line:Col": f"{f.line}:{f.column}",
            "Span": f"{f.start}-{f.end}",
            "Detector": f.source,
            "Match": f.text if reveal else "•" * min(f.end - f.start, 12),
        }
        for f in findings
    ]


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    """Count per entity type, most frequent first (ties alphabetical)."""
    counts = Counter(f.entity_type for f in findings)
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def worst_severity(findings: Iterable[Finding]) -> str | None:
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    return min((f.severity for f in findings), key=order.__getitem__, default=None)


def download_name(uploaded: str | None) -> str:
    """``app.log`` -> ``app.redacted.log``; pasted text -> ``redacted.txt``."""
    if not uploaded:
        return "redacted.txt"
    # keep only a plain base name: a browser-supplied name is untrusted
    base = os.path.basename(uploaded.replace("\\", "/")) or "input.txt"
    stem, ext = os.path.splitext(base)
    return f"{stem or 'input'}.redacted{ext or '.txt'}"


def privacy_status(address: str | None, gather_usage_stats: bool, guard: bool) -> PrivacyStatus:
    """Whether the page can truthfully promise local-only processing.

    Streamlit's own defaults undermine that promise: it listens on every
    interface and sends browser usage statistics. ``safestream ui`` turns both
    off; this checks the running server so the banner never claims more than
    holds (e.g. when the page is started with plain ``streamlit run``).
    """
    issues: list[str] = []
    if not _is_loopback(address):
        issues.append(
            f"The server listens on {address or 'all interfaces'!s}, so other machines can "
            "reach this page. Start it with `safestream ui` (binds 127.0.0.1)."
        )
    if gather_usage_stats:
        issues.append(
            "Streamlit usage statistics are enabled and are sent from your browser. Start "
            "the page with `safestream ui`, or pass --browser.gatherUsageStats false."
        )
    if not guard:
        issues.append("The offline network guard is not active in this process.")
    return PrivacyStatus(not issues, tuple(issues))


def _is_loopback(address: str | None) -> bool:
    if not address:
        return False  # Streamlit's default: every interface
    if address == "localhost":
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


SAMPLE_TEXT = """\
2026-09-30T10:14:02Z INFO  user signup email=maria.garcia@corpmail.example phone=+1 415 555 0134
2026-09-30T10:14:03Z DEBUG payment card=4111 1111 1111 1111 ssn: 123-45-6789
2026-09-30T10:14:05Z WARN  deploy used AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE from 10.0.12.7
2026-09-30T10:14:07Z ERROR webhook https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
2026-09-30T10:14:09Z INFO  db url postgres://app:s3cr3t-Pa55w0rd@db.internal:5432/prod
"""


# -- large files ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LargeResult:
    """Outcome of redacting an upload too big to analyse in the page."""

    stats: RedactionStats
    output_path: str
    input_bytes: int
    output_bytes: int
    seconds: float
    workers: int


# Scratch directories created for large files, removed when the server exits.
_WORKDIRS: set[str] = set()


def _cleanup_workdirs() -> None:
    for path in list(_WORKDIRS):
        discard_workdir(path)


atexit.register(_cleanup_workdirs)


def new_workdir() -> str:
    """A private (0700) scratch directory for one large-file run."""
    path = tempfile.mkdtemp(prefix="safestream-ui-")
    _WORKDIRS.add(path)
    return path


def discard_workdir(path: str | None) -> None:
    if path:
        shutil.rmtree(path, ignore_errors=True)
        _WORKDIRS.discard(path)


def spool_upload(src: BinaryIO, dest: str, *, chunk_size: int = 1 << 20) -> int:
    """Copy an upload to ``dest`` in fixed-size blocks; refuse binary content.

    Reading block by block never materialises a second full copy of the file:
    Streamlit already holds the upload in memory, and this adds one block.
    """
    total = 0
    with open(dest, "wb") as out:
        while block := src.read(chunk_size):
            if total == 0 and b"\0" in block[:_BINARY_SNIFF]:
                raise InputError(
                    "This looks like a binary file. Upload text (.txt, .log, .json, .csv)."
                )
            out.write(block)
            total += len(block)
    return total


def read_head(path: str, n_chars: int = PREVIEW_CHARS) -> str:
    """The first ``n_chars`` of a file, decoded exactly as the redaction reads it."""
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        return f.read(n_chars)


def default_workers() -> int:
    return os.cpu_count() or 1


def estimate_seconds(size_bytes: int, workers: int) -> float:
    """A rough duration for the progress message (throughput varies with content)."""
    return size_bytes / (_BYTES_PER_SECOND_PER_CORE * max(1, workers))


def redact_large(
    redactor: Redactor, in_path: str, out_path: str, *, workers: int | None = None
) -> LargeResult:
    """Redact a file on disk with the streaming engine, in parallel when possible.

    This is the CLI's own path: memory stays constant however big the file is,
    the output is byte-identical to a single-core run, and each worker process
    runs under the offline network guard.
    """
    from safestream_redactor.parallel import redact_file_parallel

    n = workers or default_workers()
    started = time.monotonic()
    if n > 1:
        outcome = redact_file_parallel(redactor, in_path, out_path, workers=n, offline_guard=True)
        stats = outcome.stats
    else:
        stats = redactor.redact_file(in_path, out_path)
    return LargeResult(
        stats=stats,
        output_path=out_path,
        input_bytes=os.path.getsize(in_path),
        output_bytes=os.path.getsize(out_path),
        seconds=time.monotonic() - started,
        workers=n,
    )


def counts_severity(counts: dict[str, int]) -> str | None:
    """Highest severity among per-type counts (the large-file summary)."""
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    levels = (severity_for(EntityType(name)) for name, n in counts.items() if n)
    return min(levels, key=order.__getitem__, default=None)


def save_destination(folder: str, uploaded: str | None) -> Path:
    """A path in ``folder`` for the redacted copy that never overwrites a file."""
    directory = Path(folder).expanduser()
    if not directory.is_dir():
        raise InputError(f"{directory} is not an existing folder.")
    target = directory / download_name(uploaded)
    stem, suffix = target.name.rsplit(".redacted", 1)
    n = 1
    while target.exists():
        target = directory / f"{stem}.redacted-{n}{suffix}"
        n += 1
    return target


def save_output(result: LargeResult, destination: Path) -> Path:
    """Move a large-file output to ``destination`` (copying across filesystems)."""
    shutil.move(result.output_path, destination)
    return destination


# -- chunk inspector ----------------------------------------------------------
#
# The inspector replays the streaming engine one detection pass at a time. Its
# numbers were measured in Chromium against real engine output (main-thread
# work per step; ~50 ms is the usual threshold before a page feels sluggish):
#
# * chunk size: the engine never emits less than ``overlap`` per pass, and every
#   UI configuration needs an 8,192-char overlap, so smaller chunks change
#   nothing. One step then shows 8,192 (context) + 8,192 (emitted) + 8,192
#   (carried) chars. A 16,384 chunk cost 42.8 ms/step; 65,536 cost 58.4 ms with
#   nothing retained, so only 1x and 2x the overlap are offered.
# * retention: 5 full-text steps cost 11.8 ms/step (967 DOM nodes); 10 cost 47 ms
#   and 20 cost 99 ms (visible lag). Older steps live on as table rows.
# * pacing: below ~16 ms between steps the browser queues updates; from 50 ms it
#   kept up in every run, so 50 ms is the floor. 500 ms (2 steps/s) is a reading
#   pace, a UX choice. 2,000 ms suits presenting.

INSPECTOR_RETAINED = 5
PACING_MIN_MS = 50
PACING_DEFAULT_MS = 500
PACING_MAX_MS = 2000


@dataclass(frozen=True, slots=True)
class ChunkTelemetry:
    """One emitted segment of the streaming engine, as the inspector shows it.

    Offsets are absolute in the inspected text. The pass scanned
    ``[window_start, window_end)``: read-only context up to ``emit_start``, the
    emitted segment ``[emit_start, emit_end)``, then ``carried`` characters held
    back for the next pass.
    """

    index: int
    window_start: int
    emit_start: int
    emit_end: int
    window_end: int
    carried: int
    retreated_by: int  # chars the boundary moved left to keep an entity whole
    deferred_passes: int  # preceding passes pinned by a detection on the boundary
    final: bool
    line_start: int  # 1-based lines covered by the emitted segment
    line_end: int
    findings: tuple[Finding, ...]
    straddlers: tuple[int, ...]  # indices into findings held back by a retreat
    detect_ms: float

    @property
    def planned_end(self) -> int:
        """Where the boundary would have been without the retreat."""
        return self.emit_end + self.retreated_by


def inspector_chunk_sizes(redactor: Redactor) -> tuple[int, int]:
    """The chunk sizes the inspector offers: 1x and 2x the effective overlap.

    The engine emits at least ``overlap`` characters per pass, so any smaller
    chunk behaves exactly like this one.
    """
    base = max(redactor.overlap, redactor.min_safe_overlap, 1)
    return base, 2 * base


def trace_chunks(redactor: Redactor, text: str) -> Iterator[ChunkTelemetry]:
    """Replay the streaming engine over ``text``, one record per emitted segment.

    Uses the engine's own ``on_window`` observer, so the geometry shown is what
    the engine did, not a re-derivation of it.
    """
    traces: list[WindowTrace] = []
    tracker = LineTracker()
    stream = redactor.detect_stream(_chunks(text, redactor.chunk_size), on_window=traces.append)
    offset = 0
    previous_retreat = 0
    index = 0
    while True:
        started = time.perf_counter()
        try:
            segment, detections = next(stream)
        except StopIteration:
            return
        elapsed = (time.perf_counter() - started) * 1000
        batch, traces[:] = list(traces), []
        pass_ = batch[-1]  # the pass that emitted; any before it were pinned
        deferred = len(batch) - 1
        end = offset + len(segment)
        line_start, _ = tracker.locate(segment, offset, offset)
        findings: list[Finding] = []
        for det in detections:
            start = offset + det.start
            line, column = tracker.locate(segment, offset, start)
            findings.append(_finding(redactor, det, start, offset + det.end, line, column))
        line_end, _ = tracker.locate(segment, offset, max(offset, end - 1))
        tracker.finish(segment, offset)
        # an entity held back (by the previous pass's retreat, or by pinned passes)
        # is emitted whole at the start of this segment
        held = previous_retreat > 0 or deferred > 0
        straddlers = tuple(i for i, f in enumerate(findings) if held and f.start == offset)
        retreated = 0 if pass_.final else pass_.planned_emit - pass_.emit_len
        yield ChunkTelemetry(
            index=index,
            window_start=offset - pass_.prefix_len,
            emit_start=offset,
            emit_end=end,
            window_end=offset + pass_.buffer_len,
            carried=pass_.buffer_len - pass_.emit_len,
            retreated_by=retreated,
            deferred_passes=deferred,
            final=pass_.final,
            line_start=line_start,
            line_end=line_end,
            findings=tuple(findings),
            straddlers=straddlers,
            detect_ms=elapsed,
        )
        previous_retreat = retreated
        offset = end
        index += 1


def flatten_findings(chunks: Iterable[ChunkTelemetry]) -> list[Finding]:
    """Every finding of a trace, in order (build once; see :func:`window_findings`)."""
    return [f for c in chunks for f in c.findings]


def window_findings(flat: Sequence[Finding], start: int, end: int) -> list[Finding]:
    """The findings in ``flat`` that overlap ``[start, end)``, in order.

    Findings are sorted and non-overlapping, so their ends are sorted too and a
    bisection finds the first candidate: O(log n) per step, not O(n).
    """
    i = bisect_left(flat, start + 1, key=lambda f: f.end)
    out: list[Finding] = []
    for f in flat[i:]:
        if f.start >= end:
            break
        out.append(f)
    return out


def _marked(text: str, start: int, end: int, findings: Iterable[Finding]) -> str:
    """Escaped ``text[start:end]`` with findings (clipped to the range) marked."""
    out: list[str] = []
    cursor = start
    for f in findings:
        s_, e_ = max(f.start, start), min(f.end, end)
        if e_ <= s_:
            continue
        out.append(html.escape(text[cursor:s_]))
        tip = f"{f.entity_type} · {f.severity} · {f.confidence:.2f} · line {f.line}:{f.column}"
        out.append(
            f'<mark style="background:{SEVERITY_COLORS[f.severity]}" title="{html.escape(tip)}">'
            f"{html.escape(text[s_:e_])}</mark>"
        )
        cursor = e_
    out.append(html.escape(text[cursor:end]))
    return "".join(out)


def window_html(text: str, chunk: ChunkTelemetry, findings: list[Finding]) -> str:
    """The scanned window as three bands: context, emitted segment, carried tail.

    When the boundary retreated, a marker shows where the planned cut would have
    split an entity.
    """
    parts = ['<pre class="ss-view ss-window">']
    if chunk.emit_start > chunk.window_start:
        parts.append(
            '<span class="ss-band ss-prefix" title="read-only context (already emitted)">'
            f"{_marked(text, chunk.window_start, chunk.emit_start, findings)}</span>"
        )
    parts.append(
        '<span class="ss-band ss-emit" title="emitted by this pass">'
        f"{_marked(text, chunk.emit_start, chunk.emit_end, findings)}</span>"
    )
    parts.append('<span class="ss-cut" title="actual boundary"></span>')
    if chunk.window_end > chunk.emit_end:
        carry = [
            '<span class="ss-band ss-carry" title="carried to the next pass">',
        ]
        if chunk.retreated_by:
            carry.append(_marked(text, chunk.emit_end, chunk.planned_end, findings))
            carry.append(
                '<span class="ss-planned" title="planned boundary: it would have cut '
                f'this entity, so it moved back {chunk.retreated_by} chars"></span>'
            )
            carry.append(_marked(text, chunk.planned_end, chunk.window_end, findings))
        else:
            carry.append(_marked(text, chunk.emit_end, chunk.window_end, findings))
        carry.append("</span>")
        parts.extend(carry)
    parts.append("</pre>")
    return "".join(parts)


def segment_html(text: str, chunk: ChunkTelemetry, *, redacted: bool) -> str:
    """The emitted segment alone, original or redacted (findings re-based)."""
    segment = text[chunk.emit_start : chunk.emit_end]
    local = [
        replace(f, start=f.start - chunk.emit_start, end=f.end - chunk.emit_start)
        for f in chunk.findings
    ]
    return highlight_html(segment, local, redacted=redacted, limit=len(segment))


def trace_rows(chunks: Iterable[ChunkTelemetry]) -> list[dict[str, object]]:
    """Archive table: one row per pass, offsets only (no text, so it stays small)."""
    return [
        {
            "Pass": c.index,
            "Window": f"{c.window_start}-{c.window_end}",
            "Emitted": f"{c.emit_start}-{c.emit_end}",
            "Lines": f"{c.line_start}-{c.line_end}",
            "Carried": c.carried,
            "Retreat": c.retreated_by,
            "Deferred": c.deferred_passes,
            "Findings": len(c.findings),
            "Held whole": len(c.straddlers),
            "Detect ms": round(c.detect_ms, 1),
        }
        for c in chunks
    ]


def pass_html(
    text: str,
    chunks: Sequence[ChunkTelemetry],
    flat: Sequence[Finding],
    i: int,
    *,
    retained: int = INSPECTOR_RETAINED,
) -> str:
    """One inspector step as a single HTML block.

    Header, notices, the scanned window, the redacted segment, and the last
    ``retained`` segments are one element on purpose: in the browser each
    separate Streamlit element on a timer-driven step costs a React remount, a
    style recalculation, and a sanitiser pass. Profiling showed that churn, not
    the text, dominated the cost of a step.
    """
    c = chunks[i]
    out = [
        '<div class="ss-pass">',
        f"<p><strong>Pass {i + 1} of {len(chunks)}</strong> · scanned "
        f"{c.window_start:,}-{c.window_end:,} · emitted {c.emit_start:,}-{c.emit_end:,} "
        f"(lines {c.line_start}-{c.line_end}) · carried {c.carried:,} · detect "
        f"{c.detect_ms:.1f} ms</p>",
    ]
    if c.retreated_by:
        out.append(
            '<div class="ss-note ss-warn">The planned boundary at '
            f"{c.planned_end:,} would have cut an entity in two, so it moved back "
            f"{c.retreated_by} chars (red dashed line). The entity is emitted whole by "
            "the next pass.</div>"
        )
    if c.straddlers:
        names = ", ".join(html.escape(c.findings[j].entity_type) for j in c.straddlers)
        out.append(
            '<div class="ss-note">Held back by the previous pass and emitted whole '
            f"here: {names}.</div>"
        )
    if c.deferred_passes:
        out.append(
            f'<div class="ss-note">{c.deferred_passes} earlier pass(es) emitted nothing: '
            "a detection covered the whole planned segment, so the engine read more "
            "text first.</div>"
        )
    out.append(
        '<div class="ss-panes"><div><p><strong>Scanned window</strong><br><small>dim: '
        "read-only context · plain: emitted · dotted: carried forward</small></p>"
        + window_html(text, c, window_findings(flat, c.window_start, c.window_end))
        + "</div><div><p><strong>Redacted segment</strong><br><small>what this pass "
        "writes to the output</small></p>" + segment_html(text, c, redacted=True) + "</div></div>"
    )
    recent = list(chunks[max(0, i - retained + 1) : i + 1])[::-1]
    out.append(f"<p><strong>Last {len(recent)} emitted segments</strong> (newest first)</p>")
    for r in recent:
        out.append(
            f'<div class="ss-seg-title">Pass {r.index + 1} · lines {r.line_start}-'
            f"{r.line_end} · {len(r.findings)} finding(s)</div>"
            + segment_html(text, r, redacted=False)
        )
    out.append("</div>")
    return "".join(out)
