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
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
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
