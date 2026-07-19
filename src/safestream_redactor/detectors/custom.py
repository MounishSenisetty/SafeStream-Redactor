"""User-supplied words, phrases, and regexes (from the CLI or API)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from safestream_redactor.entities import Detection, EntityType


class CustomDetector:
    name = "custom"

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
            self._regexes.append(re.compile(p, flags))

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
