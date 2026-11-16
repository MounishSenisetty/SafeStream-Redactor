"""User-supplied words, phrases, and regexes (from the CLI or API)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType

# Whitespace between the words of a custom phrase: any run of blanks or line
# breaks, bounded so a phrase's span stays bounded for the streaming engine.
_GAP = r"\s{1,16}"


def _word_pattern(word: str) -> str:
    """A literal custom word as a regex: whole words only, any whitespace inside.

    ``ann`` must not redact the middle of ``annual`` or ``banner``, and the phrase
    ``Project Falcon`` must still match ``Project  Falcon`` or a line-wrapped
    ``Project\nFalcon``. A boundary is only required on an edge that is a word
    character, so a word such as ``#tag`` or ``a.b*c`` still matches next to
    punctuation.
    """
    body = _GAP.join(re.escape(part) for part in word.split())
    head = r"\b" if re.match(r"\w", word) else ""
    tail = r"\b" if re.search(r"\w\Z", word) else ""
    return f"{head}{body}{tail}"


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
        # Longest first: regex alternation is leftmost-*first*, not longest, so
        # with ``Jo|John`` the text "John" matched only "Jo" and "hn" leaked
        # through unredacted. Sorting (and de-duplicating) makes a longer phrase
        # always win over any word that is its prefix.
        words = sorted({w.strip() for w in words if w.strip()}, key=lambda w: (-len(w), w))
        if words:
            joined = "|".join(_word_pattern(w) for w in words)
            self._regexes.append(re.compile(joined, flags))
        for p in patterns:
            try:
                # ^ and $ mean the start and end of a line, as people expect when
                # they write a rule for a line-oriented log
                self._regexes.append(re.compile(p, flags | re.MULTILINE))
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
