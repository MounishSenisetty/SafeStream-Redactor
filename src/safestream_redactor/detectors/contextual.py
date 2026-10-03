"""Tier 3: contextual heuristics.

Looks at the text surrounding each detection and nudges its confidence up or
down, and promotes otherwise-ambiguous spans (like a bare 9-digit number next
to "ssn:") into detections of their own.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.deterministic import NativeBacked
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

_NUMBER_TYPES = frozenset({EntityType.CREDIT_CARD, EntityType.PHONE, EntityType.SSN})


def _embedded_number(text: str, det: Detection) -> bool:
    """A card/phone/SSN match with letters or digits on BOTH sides sits inside a
    longer alphanumeric token (0x5290840009852788 6E0F... is an Ethereum address,
    not a card). It is not a standalone number, and redacting just that run would
    leave the rest of the token in the clear while hiding the token's real type."""
    return (
        det.entity_type in _NUMBER_TYPES
        and det.start > 0
        and det.end < len(text)
        and text[det.start - 1].isalnum()
        and text[det.end].isalnum()
    )


# Detections whose ``text`` is exactly ``text[start:end]``: the built-in tiers.
# The native ``adjust`` reads the span from the text, so only these may use it;
# a plugin's detection is adjusted in Python.
_SLICE_SOURCES = frozenset(
    {"deterministic", "labeled_identifier", "entropy", "compound_secret", "contextual"}
)


class ContextualScorer(NativeBacked):
    """Adjusts confidences in place and contributes trigger-gated detections."""

    name = "contextual"
    # Emits at most a 9-digit bare-SSN span, but reads up to ``window`` chars of
    # left context to gate it; declare both so the engine preserves that context.
    requirements = StreamingRequirements(max_span=9, left_context=48, right_context=1)

    def __init__(
        self,
        window: int = 48,
        suppress_window: int = 16,
        boost: float = BOOST,
        suppress: float = SUPPRESS,
        backend: str = "python",
    ) -> None:
        self.window = window
        self.suppress_window = suppress_window
        self.boost = boost
        self.suppress = suppress
        # optional native core: same trigger decisions (it lower-cases exactly as
        # str.lower() does for ASCII triggers), the arithmetic stays here
        self._attach_native(backend)
        self._codes: dict[EntityType, int] = {}
        if self._native is not None:  # pragma: no cover - requires native extension
            names = [name for name, _words in self._native.context_triggers()[0]]
            self._codes = {t: names.index(t.value) for t in _BOOST_TRIGGERS}

    def _decide(self, text: str, det: Detection) -> tuple[bool, bool]:
        """(boost, suppress) for one detection: the Python reference."""
        context = text[max(0, det.start - self.window) : det.start].lower()
        triggers = _BOOST_TRIGGERS.get(det.entity_type, ())
        boosted = any(t in context for t in triggers)
        # suppression looks at the match itself plus a tight window, so a
        # neighbouring entity containing e.g. "example" can't poison it
        near = text[max(0, det.start - self.suppress_window) : det.start].lower()
        suppressed = any(t in near or t in det.text.lower() for t in _SUPPRESS_TRIGGERS)
        return boosted, suppressed

    def _apply(self, det: Detection, boosted: bool, suppressed: bool) -> None:
        if boosted:
            det.confidence = min(1.0, det.confidence + self.boost)
            det.meta["context"] = "boosted"
        if suppressed:
            det.confidence = max(0.0, det.confidence - self.suppress)
            det.meta["context"] = "suppressed"

    def adjust(self, text: str, detections: list[Detection]) -> list[Detection]:
        flags = None
        if self._native is not None and detections:  # pragma: no cover - native only
            flags = self._native_call(
                self._native.adjust_text,
                text,
                [(d.start, d.end, self._codes.get(d.entity_type, 0)) for d in detections],
                self.window,
                self.suppress_window,
            )
        for i, det in enumerate(detections):
            if flags is not None and det.source in _SLICE_SOURCES:  # pragma: no cover
                self._apply(det, bool(flags[i] & 1), bool(flags[i] & 2))
            else:
                self._apply(det, *self._decide(text, det))
            if _embedded_number(text, det):  # shared Python check, both backends
                det.confidence = 0.0
                det.meta["context"] = "embedded"
        return detections

    def detect(self, text: str) -> list[Detection]:
        """Trigger-gated detections that tier 1 deliberately skips."""
        if self._native is not None:  # pragma: no cover - requires native extension
            spans = self._native_call(self._native.scan_bare_ssn_text, text, self.window)
            if spans is not None:
                return [self._bare_ssn(text, s, e) for s, e in spans]
        found: list[Detection] = []
        for m in _BARE_SSN.finditer(text):
            context = text[max(0, m.start() - self.window) : m.start()].lower()
            if any(t in context for t in _BOOST_TRIGGERS[EntityType.SSN]):
                found.append(self._bare_ssn(text, m.start(), m.end()))
        return found

    def _bare_ssn(self, text: str, start: int, end: int) -> Detection:
        return Detection(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=EntityType.SSN,
            confidence=0.8,
            source=self.name,
        )
