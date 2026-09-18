"""User-supplied words, phrases, and regexes (from the CLI or API)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType


class CustomDetector:
    name = "custom"
    # User-supplied words are literals (bounded by their own length); user
    # patterns are arbitrary, so the span a custom regex can match is not known
    # ahead of time. We declare the default overlap as the assumed bound and
    # document that a custom pattern matching text longer than the configured
    # overlap falls outside the single-span boundary guarantee (Theorem 1).
    requirements = StreamingRequirements(max_span=8 * 1024)

    def __init__(
        self,
        words: Iterable[str] = (),
        patterns: Iterable[str] = (),
        case_sensitive: bool = False,
    ) -> None:
        flags = 0 if case_sensitive else re.IGNORECASE
        self._regexes: list[re.Pattern[str]] = []
        words = [w for w in words if w]
        if words:
            joined = "|".join(re.escape(w) for w in words)
            self._regexes.append(re.compile(joined, flags))
        for p in patterns:
            try:
                self._regexes.append(re.compile(p, flags))
            except re.error as exc:
                # Surface a clear configuration error (which pattern, why) rather
                # than a bare re.error, so a mistyped --custom-regex fails loudly
                # and actionably instead of leaking regex-engine internals.
                raise ValueError(f"invalid custom pattern {p!r}: {exc}") from exc

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for regex in self._regexes:
            for m in regex.finditer(text):
                if not m.group():
                    continue
                found.append(
                    Detection(
                        start=m.start(),
                        end=m.end(),
                        text=m.group(),
                        entity_type=EntityType.CUSTOM,
                        confidence=1.0,
                        source=self.name,
                    )
                )
        return found
