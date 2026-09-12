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
from safestream_redactor.entities import Detection, EntityType

# The longest value span this tier emits, and the largest gap between a cue and
# its value. Both feed the engine's overlap sizing.
_MAX_VALUE = 64
_CUE_WINDOW = 96

# Separators allowed between a cue and its value: ``: = # - .`` and whitespace,
# plus short connective words ("is", "no", "number", "#"). Kept tight so a cue
# cannot reach across a sentence to a coincidental number.
_SEP = r"(?:\s*(?:number|num|no|id|code|#|:|=|-|\.|is|of)\b)*\s*[:=#\-.]?\s*"

# Each rule: (cue alternation, value pattern, entity type, confidence).
# The value pattern must use a single capturing group around the emitted span.
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
        r"(\+?\d[\d\s().-]{6,}\d)",
        EntityType.PHONE,
        0.8,
    ),
    # Payment-card numbers named by a label
    (
        r"card(?:\s*(?:no|number|#))?|credit\s*card|debit\s*card|pan",
        r"((?:\d[ -]?){13,19})",
        EntityType.CREDIT_CARD,
        0.85,
    ),
    # Financial account / routing / IBAN / SWIFT
    (
        r"account|acct|routing|aba|iban|swift|bic|bank|sort\s*code",
        r"([A-Z]{2}\d{2}[A-Z0-9]{6,30}|\d[\d\s-]{4,}\d)",
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
        r"([A-Za-z]{0,6}[-/]?\d[A-Za-z0-9-]{2,})",
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


class LabeledIdentifierDetector:
    """Promotes label-anchored identifiers (``Student ID: 202184673``) to redactions."""

    name = "labeled_identifier"
    requirements = StreamingRequirements(
        max_span=_MAX_VALUE, left_context=_CUE_WINDOW, right_context=8
    )

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for pattern, etype, conf in _COMPILED:
            for m in pattern.finditer(text):
                # group(1) is the value; emit only that span (never the label).
                start, end = m.start(1), m.end(1)
                value = m.group(1)
                # Guard: the gap between cue and value must be small, so a cue
                # cannot anchor a number far away in the text.
                if start - m.start() - len(value) > _CUE_WINDOW:
                    continue
                found.append(
                    Detection(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=etype,
                        confidence=conf,
                        source=self.name,
                        meta={"cue": m.group(0)[: m.start(1) - m.start()].strip()[:32]},
                    )
                )
        return found
