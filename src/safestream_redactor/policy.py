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

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = RedactionMode(self.mode)
        if self.mode is RedactionMode.PSEUDONYMIZE and not self.hmac_key:
            raise ValueError("pseudonymize mode requires an hmac_key")

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
            return f"<{detection.entity_type.value.upper()}_{digest.hexdigest()[:10]}>"
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
