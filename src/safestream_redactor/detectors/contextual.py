"""Tier 3: contextual heuristics.

Looks at the text surrounding each detection and nudges its confidence up or
down, and promotes otherwise-ambiguous spans (like a bare 9-digit number next
to "ssn:") into detections of their own.
"""

from __future__ import annotations

import re

from safestream_redactor.entities import Detection, EntityType

# words near a detection that make it MORE likely to be real, per type
_BOOST_TRIGGERS: dict[EntityType, tuple[str, ...]] = {
    EntityType.SSN: ("ssn", "social security", "social-security"),
    EntityType.PHONE: ("phone", "tel", "mobile", "cell", "fax", "call"),
    EntityType.CREDIT_CARD: ("card", "visa", "mastercard", "amex", "cc", "payment"),
    EntityType.EMAIL: ("email", "e-mail", "mail", "contact"),
    EntityType.API_KEY: ("key", "secret", "token", "password", "credential", "auth"),
    EntityType.IPV4: ("ip", "host", "server", "addr"),
    EntityType.IPV6: ("ip", "host", "server", "addr"),
}

# words that make ANY nearby detection likely to be a placeholder / test value
_SUPPRESS_TRIGGERS: tuple[str, ...] = (
    "example",
    "sample",
    "dummy",
    "test",
    "fake",
    "placeholder",
    "lorem",
    "xxx-xx",
)

# a bare 9-digit number is too ambiguous for tier 1, but next to an SSN
# trigger word it almost certainly is one
_BARE_SSN = re.compile(r"(?<![\d-])\d{9}(?![\d-])")

BOOST = 0.2
SUPPRESS = 0.4


class ContextualScorer:
    """Adjusts confidences in place and contributes trigger-gated detections."""

    name = "contextual"

    def __init__(
        self,
        window: int = 48,
        suppress_window: int = 16,
        boost: float = BOOST,
        suppress: float = SUPPRESS,
    ) -> None:
        self.window = window
        self.suppress_window = suppress_window
        self.boost = boost
        self.suppress = suppress

    def adjust(self, text: str, detections: list[Detection]) -> list[Detection]:
        for det in detections:
            context = text[max(0, det.start - self.window) : det.start].lower()
            triggers = _BOOST_TRIGGERS.get(det.entity_type, ())
            if any(t in context for t in triggers):
                det.confidence = min(1.0, det.confidence + self.boost)
                det.meta["context"] = "boosted"
            # suppression looks at the match itself plus a tight window, so a
            # neighbouring entity containing e.g. "example" can't poison it
            near = text[max(0, det.start - self.suppress_window) : det.start].lower()
            if any(t in near or t in det.text.lower() for t in _SUPPRESS_TRIGGERS):
                det.confidence = max(0.0, det.confidence - self.suppress)
                det.meta["context"] = "suppressed"
        return detections

    def detect(self, text: str) -> list[Detection]:
        """Trigger-gated detections that tier 1 deliberately skips."""
        found: list[Detection] = []
        for m in _BARE_SSN.finditer(text):
            context = text[max(0, m.start() - self.window) : m.start()].lower()
            if any(t in context for t in _BOOST_TRIGGERS[EntityType.SSN]):
                found.append(
                    Detection(
                        start=m.start(),
                        end=m.end(),
                        text=m.group(),
                        entity_type=EntityType.SSN,
                        confidence=0.8,
                        source=self.name,
                    )
                )
        return found
