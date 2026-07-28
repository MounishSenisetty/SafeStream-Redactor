"""Redaction policies: how a detected span is rewritten."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum

from safestream_redactor.entities import Detection, EntityType


class RedactionMode(str, Enum):
    REPLACE = "replace"
    MASK = "mask"
    # Deterministic keyed tokens: the same input always maps to the same token,
    # which is the point (referential integrity across a corpus) but is also a
    # limitation — it leaks value equality, and because it is deterministic and
    # keyed, an attacker who knows the key can brute-force any low-cardinality
    # domain (all SSNs, all phone numbers) to invert the mapping. Use a strong,
    # secret, high-entropy key and treat pseudonymized output as reversible by
    # anyone with that key, not as anonymized. See SECURITY.md.
    PSEUDONYMIZE = "pseudonymize"


@dataclass(slots=True)
class RedactionPolicy:
    """Controls the replacement text for each detection.

    ``replacements`` maps an :class:`EntityType` to a fixed string and takes
    priority over everything else; ``mode`` decides what happens to the rest.
    """

    mode: RedactionMode = RedactionMode.REPLACE
    replacement: str = "[REDACTED]"
    replacements: dict[EntityType, str] = field(default_factory=dict)
    mask_keep_last: int = 4
    mask_char: str = "*"
    hmac_key: bytes | None = None
    # Hex digits kept from the HMAC in pseudonymize mode. 16 hex = 64 bits,
    # which pushes the birthday-collision point past ~4 billion distinct
    # values; the old 10-hex (40-bit) default collided around ~1 million,
    # realistic for a large log with many distinct secrets. Minimum 8.
    pseudonym_length: int = 16

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = RedactionMode(self.mode)
        if self.mode is RedactionMode.PSEUDONYMIZE and not self.hmac_key:
            raise ValueError("pseudonymize mode requires an hmac_key")
        if not 8 <= self.pseudonym_length <= 64:
            raise ValueError("pseudonym_length must be between 8 and 64 hex digits")

    def render(self, detection: Detection) -> str:
        """The string that replaces ``detection`` in the output."""
        override = self.replacements.get(detection.entity_type)
        if override is not None:
            return override
        if self.mode is RedactionMode.MASK:
            keep = max(0, self.mask_keep_last)
            visible = detection.text[-keep:] if keep else ""
            return self.mask_char * max(0, len(detection.text) - keep) + visible
        if self.mode is RedactionMode.PSEUDONYMIZE:
            assert self.hmac_key is not None
            digest = hmac.new(self.hmac_key, detection.text.encode(), hashlib.sha256)
            token = digest.hexdigest()[: self.pseudonym_length]
            return f"<{detection.entity_type.value.upper()}_{token}>"
        return self.replacement

    def apply(self, text: str, detections: list[Detection]) -> str:
        """Rewrite ``text`` with every detection replaced.

        ``detections`` must be sorted and non-overlapping (the pipeline
        guarantees this via :func:`~safestream_redactor.entities.resolve_overlaps`).
        """
        if not detections:
            return text
        parts: list[str] = []
        cursor = 0
        for det in detections:
            parts.append(text[cursor : det.start])
            parts.append(self.render(det))
            cursor = det.end
        parts.append(text[cursor:])
        return "".join(parts)
