"""Run reports: auditable evidence of what a redaction run did.

Compliance workflows need to *file* what a run changed — how many entities of
which types, over how many files and characters. The schema here is
content-free by construction: it carries only entity-type names, counts, and
sizes, never the matched text, so the report itself can be stored and shipped
without weakening the privacy guarantee.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from safestream_redactor.entities import Detection


@dataclass(slots=True)
class RedactionStats:
    """Counters accumulated while redacting; safe to merge across files/workers."""

    counts: Counter[str] = field(default_factory=Counter)
    chars_in: int = 0
    chars_out: int = 0
    # U+FFFD replacement characters seen in the input. These usually mean the
    # source had bytes that could not be decoded as the chosen encoding and were
    # substituted — text that no detector then scanned, so a secret in those
    # bytes could pass through unredacted. Surfaced instead of silently ignored.
    decode_replacements: int = 0

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def add_segment(self, segment: str, redacted: str, detections: Iterable[Detection]) -> None:
        self.chars_in += len(segment)
        self.chars_out += len(redacted)
        self.decode_replacements += segment.count("�")
        for det in detections:
            self.counts[det.entity_type.value] += 1

    def merge(self, other: RedactionStats) -> None:
        self.counts.update(other.counts)
        self.chars_in += other.chars_in
        self.chars_out += other.chars_out
        self.decode_replacements += other.decode_replacements

    def summary(self) -> str:
        """One-line human summary, e.g. ``5 detection(s): email=3, ssn=2``."""
        if not self.counts:
            return "0 detections"
        per_type = ", ".join(f"{t}={n}" for t, n in sorted(self.counts.items()))
        return f"{self.total} detection(s): {per_type}"


def build_report(
    stats: RedactionStats,
    *,
    files: int,
    duration_seconds: float,
    version: str,
) -> dict[str, object]:
    """A JSON-serialisable run report. Contains counts and sizes, never content."""
    return {
        "tool": "safestream-redactor",
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
        "duration_seconds": round(duration_seconds, 3),
        "total_detections": stats.total,
        "detections_by_type": dict(sorted(stats.counts.items())),
        "chars_in": stats.chars_in,
        "chars_out": stats.chars_out,
        "decode_replacements": stats.decode_replacements,
    }


def write_report(path: str, report: dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
