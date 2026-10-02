"""Label-anchored identifier detection (a high-precision contextual cascade).

Many high-value identifiers have **no distinctive intrinsic form** — a student
id, an account number, a medical-record number, a date of birth, or a bare
national-id number is just a run of digits or alphanumerics, indistinguishable
from an order total or a version string. The deterministic tier deliberately
does not flag them, because doing so unconditionally would redact every number
in a document and destroy precision.

They *are* recoverable, though, when the text names them: ``Student ID:
202184673``, ``Account Number 102294080031``, ``DOB: 03/08/1996``. This detector
implements that cascade — a **cue word immediately to the left promotes an
otherwise-ambiguous value into a redaction**, and only then. Precision stays high
because a match requires an explicit label; recall improves because these
label-anchored identifiers are exactly the structured PII a regex core otherwise
misses.

The cue vocabulary is the standard DLP one (identity, financial, health, and
government identifiers); it is intentionally source-agnostic, not tuned to any
particular corpus. Only the **value** span is emitted (never the label), so the
redaction covers the sensitive characters and nothing more.

Streaming safety: a cue sits at most ``_CUE_WINDOW`` characters before its value,
so the whole ``cue … value`` construct fits inside one detection window; the
detector is stateless and window-pure, preserving the streaming/parallel
equivalence guarantees. It declares its :class:`StreamingRequirements`
accordingly.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.deterministic import NativeBacked
from safestream_redactor.entities import Detection, EntityType

# The longest value span this tier emits, and the largest gap between a cue and
# its value. Both feed the engine's overlap sizing.
_MAX_VALUE = 64
_CUE_WINDOW = 96

# Separators allowed between a cue and its value: ``: = # - .`` and whitespace,
# plus short connective words ("is", "no", "number", "#"). Kept tight so a cue
# cannot reach across a sentence to a coincidental number.
#
# The optional punctuation owns its trailing whitespace (``(?:[:=#\-.]\s*)?``)
# rather than sitting between two bare ``\s*``: with ``\s*[…]?\s*`` an absent
# separator leaves two adjacent ``\s*`` that backtracking splits every possible
# way, which is O(n^2) per cue on a long whitespace run (a cue followed by 32K
# spaces took ~19 s in one ``detect`` call). This form matches the same language
# with the same greedy choice, in O(n). Forms also put an en/em dash, a pointer
# (U+25BA) or a pipe between a label and its value: ``VISA NO \u2013 201512589001``.
_SEP = r"(?:\s*(?:number|num|no|id|code|#|:|=|-|\.|is|of)\b)*\s*(?:[:=#\-.\u2013\u2014\u25ba|]\s*)?"

# Each rule: (cue alternation, value pattern, entity type, confidence).
# The value pattern must use a single capturing group around the emitted span,
# and every value must be bounded to ``_MAX_VALUE`` characters: that bound is the
# ``max_span`` this tier declares to the engine's overlap sizing.
# Values are required to contain a digit (or be a formatted id) so ordinary words
# after a cue are not swept up.
_RULES: tuple[tuple[str, str, EntityType, float], ...] = (
    # National identifiers — SSN / SIN / national id number. Emitted as the
    # generic ID_NUMBER, not SSN: a *valid* SSN is already typed SSN by the
    # validated deterministic tier (and wins overlap resolution), so this rule's
    # job is to still redact a number the text explicitly labels as an SSN even
    # when it fails SSN structural validation (e.g. a 000-area placeholder) —
    # without claiming the validated SSN type for it.
    (
        r"ssn|social[\s-]?security(?:\s*(?:no|number|#))?|sin|national\s*id",
        r"(\d{3}[-\s]?\d{2}[-\s]?\d{4}|\d{9})",
        EntityType.ID_NUMBER,
        0.8,
    ),
    # Dates of birth
    (
        r"dob|date\s*of\s*birth|birth\s*date|born(?:\s*on)?",
        r"(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})",
        EntityType.DOB,
        0.8,
    ),
    # Phone / fax numbers named by a label
    (
        r"phone|tel(?:ephone)?|mobile|cell|fax|contact\s*(?:no|number)",
        # a form may split the country code off with a dash or pointer
        r"(\+?\d[\d\s().\-\u2013\u25ba]{6,61}\d)",
        EntityType.PHONE,
        0.8,
    ),
    # Payment-card numbers named by a label
    (
        r"card(?:\s*(?:no|number|#))?|credit\s*card|debit\s*card|pan",
        # 13-19 digits ending on a digit, so a trailing separator is never
        # swallowed ("card 4111 1111 1111 1111 key" must keep its space)
        r"((?:\d[ -]?){12,18}\d)",
        EntityType.CREDIT_CARD,
        0.85,
    ),
    # Financial account / routing / IBAN / SWIFT
    (
        r"account|acct|routing|aba|iban|swift|bic|bank|sort\s*code",
        # IBAN, a lender-prefixed number (MP-00291847, HELOC-8847310), or digits
        r"([A-Z]{2}\d{2}[A-Z0-9]{6,30}|[A-Z]{1,6}-\d[A-Z0-9-]{3,56}|\d[\d\s-]{4,62}\d)",
        EntityType.ID_NUMBER,
        0.8,
    ),
    # Generic sensitive identifiers — restricted to cues that reliably name a
    # *person/health/government* identifier (not business-object numbers such as
    # order/invoice/ticket, which are frequently non-personal and would cost
    # precision). Value must contain a digit so plain words are not captured.
    (
        r"student|employee|emp|staff|member|customer|client|patient|"
        r"badge|tax|medical\s*record|mrn|npi|licen[cs]e|passport|"
        r"national\s*id|registration|enrol?lment",
        r"([A-Za-z]{0,6}[-/]?\d[A-Za-z0-9-]{2,56})",
        EntityType.ID_NUMBER,
        0.75,
    ),
    # Legal / insurance / immigration reference numbers. "case" counts only with
    # "no"/"number" ("in case 2 fails" is no label); the value needs a digit.
    (
        r"case\s*(?:no|number|num)|docket|policy|claim|visa|record",
        r"([A-Za-z]{0,6}[-/]?\d[A-Za-z0-9-]{2,56})",
        EntityType.ID_NUMBER,
        0.75,
    ),
)

# One compiled pattern per rule: cue, then a bounded gap, then the value group.
_COMPILED: tuple[tuple[re.Pattern[str], EntityType, float], ...] = tuple(
    (
        re.compile(
            rf"\b(?:{cue})\b{_SEP}{value}",
            re.IGNORECASE,
        ),
        etype,
        conf,
    )
    for cue, value, etype, conf in _RULES
)


class LabeledIdentifierDetector(NativeBacked):
    """Promotes label-anchored identifiers (``Student ID: 202184673``) to redactions."""

    name = "labeled_identifier"
    requirements = StreamingRequirements(
        max_span=_MAX_VALUE, left_context=_CUE_WINDOW, right_context=8
    )

    def __init__(self, backend: str = "python") -> None:
        # Same engine selection as the deterministic tier: the optional native
        # core runs these rules byte-identically (tests/test_native_backend.py)
        # and falls back to Python when it is absent or version-skewed.
        self._attach_native(backend)

    def detect(self, text: str) -> list[Detection]:
        if self._native is not None:  # pragma: no cover - requires native extension
            spans = self._native_call(self._native.scan_labeled_text, text)
            if spans is not None:
                return [
                    det
                    for start, vstart, vend, rule in spans
                    if (det := self._detection(text, start, vstart, vend, rule)) is not None
                ]
        found: list[Detection] = []
        for rule, (pattern, _etype, _conf) in enumerate(_COMPILED):
            for m in pattern.finditer(text):
                # group(1) is the value; emit only that span (never the label).
                det = self._detection(text, m.start(), m.start(1), m.end(1), rule)
                if det is not None:
                    found.append(det)
        return found

    def _detection(
        self, text: str, start: int, vstart: int, vend: int, rule: int
    ) -> Detection | None:
        # Guard: the cue plus its gap must fit in the declared window, so a cue
        # cannot anchor a number far away in the text.
        if vstart - start > _CUE_WINDOW:
            return None
        _pattern, etype, conf = _COMPILED[rule]
        return Detection(
            start=vstart,
            end=vend,
            text=text[vstart:vend],
            entity_type=etype,
            confidence=conf,
            source=self.name,
            meta={"cue": text[start:vstart].strip()[:32]},
        )
