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

# A trigger counts only as a whole word of the text ("latest", "protest" and
# "sk_test_" hold none); the class is ASCII so the native core matches it exactly.
_SUPPRESS_WORD = re.compile(
    r"(?<![a-z0-9_])(?:" + "|".join(map(re.escape, _SUPPRESS_TRIGGERS)) + r")(?![a-z0-9_])"
)

# Only a shape-only match is demoted by a nearby trigger. Vendor-prefixed and
# checksum-validated types, field/label-anchored values, NER and plugins are not:
# a real key next to "test" leaks, a fixture value redacted costs nothing.
_SUPPRESSIBLE_SOURCES = frozenset({"deterministic", "entropy", "compound_secret", "contextual"})
_STRONG_TYPES = frozenset(
    {
        EntityType.CREDIT_CARD,  # Luhn
        EntityType.IBAN,
        EntityType.AWS_KEY,
        EntityType.AWS_SECRET,
        EntityType.GITHUB_TOKEN,
        EntityType.JWT,
        EntityType.PRIVATE_KEY,
        EntityType.SLACK_TOKEN,
        EntityType.SLACK_WEBHOOK,
        EntityType.STRIPE_KEY,
        EntityType.GOOGLE_API_KEY,
        EntityType.SENDGRID_KEY,
        EntityType.TWILIO_KEY,
        EntityType.NPM_TOKEN,
        EntityType.OPENAI_KEY,
        EntityType.ANTHROPIC_KEY,
        EntityType.URL_CREDENTIALS,
        EntityType.VENDOR_TOKEN,
        EntityType.PASSWORD_HASH,
    }
)


def _suppressible(det: Detection) -> bool:
    return det.source in _SUPPRESSIBLE_SOURCES and det.entity_type not in _STRONG_TYPES


def _word_in(text: str, lo: int, hi: int) -> bool:
    """A suppress trigger lies whole inside ``text[lo:hi]`` and is a word of the
    full text: the characters on either side, in or out of the range, are not
    ``[a-z0-9_]`` once lower-cased."""
    a, b = max(0, lo - 1), min(len(text), hi + 1)
    s = text[a:b].lower()
    limit = len(s) - (b - hi)
    return any(m.end() <= limit for m in _SUPPRESS_WORD.finditer(s, lo - a))


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
        near = max(0, det.start - self.suppress_window)
        suppressed = _word_in(text, near, det.start) or _word_in(text, det.start, det.end)
        return boosted, suppressed

    def _apply(self, det: Detection, boosted: bool, suppressed: bool) -> None:
        if boosted:
            det.confidence = min(1.0, det.confidence + self.boost)
            det.meta["context"] = "boosted"
        if suppressed and _suppressible(det):
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
