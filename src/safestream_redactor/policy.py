"""Redaction policies: how a detected span is rewritten."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum

from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.operators import (
    HASH_ALGORITHMS,
    MIN_KEY_BYTES,
    encrypt_token,
    fictionalize,
    hash_token,
)


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
    # Salted digest ("<TYPE:H:hex>"). Unkeyed unless a secret ``hash_salt`` is set;
    # see operators.py for why that matters.
    HASH = "hash"
    # Reversible, deterministic AES-256-GCM tokens ("<TYPE:E:...>") that a
    # Deanonymizer holding ``encrypt_key`` turns back into the original text.
    ENCRYPT = "encrypt"
    # Deterministic type-shaped synthetic values from reserved/never-issued
    # ranges (example.com, TEST-NET, 555-01xx). Needs ``hmac_key``.
    FICTIONALIZE = "fictionalize"


@dataclass(slots=True)
class RedactionPolicy:
    """Controls the replacement text for each detection.

    ``replacements`` maps an :class:`EntityType` to a fixed string and takes
    priority over everything else; ``mode`` decides what happens to the rest.
    """

    mode: RedactionMode = RedactionMode.REPLACE
    replacement: str = "[REDACTED]"
    replacements: dict[EntityType, str] = field(default_factory=dict)
    # Mask mode: trailing characters left visible. Capped at half the entity's
    # length when rendering, so a short value is never shown in full.
    mask_keep_last: int = 4
    mask_char: str = "*"
    # ``str`` keys are accepted and UTF-8 encoded (a TOML/CLI key is text).
    hmac_key: bytes | str | None = None
    # Hex digits kept from the HMAC in pseudonymize mode. 16 hex = 64 bits,
    # which pushes the birthday-collision point past ~4 billion distinct
    # values; the old 10-hex (40-bit) default collided around ~1 million,
    # realistic for a large log with many distinct secrets. Minimum 8.
    pseudonym_length: int = 16
    # HASH mode: digest algorithm and an optional secret salt.
    hash_algorithm: str = "sha256"
    hash_salt: bytes | str | None = None
    # ENCRYPT mode: secret key (>= 16 bytes; text keys are UTF-8 encoded).
    encrypt_key: bytes | str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = RedactionMode(self.mode)
        if isinstance(self.hmac_key, str):
            self.hmac_key = self.hmac_key.encode("utf-8")
        if isinstance(self.hash_salt, str):
            self.hash_salt = self.hash_salt.encode("utf-8")
        if isinstance(self.encrypt_key, str):
            self.encrypt_key = self.encrypt_key.encode("utf-8")
        if self.hash_algorithm not in HASH_ALGORITHMS:
            raise ValueError(f"hash_algorithm must be one of {', '.join(HASH_ALGORITHMS)}")
        if self.mode is RedactionMode.ENCRYPT:
            if not self.encrypt_key:
                raise ValueError("encrypt mode requires an encrypt_key")
            if len(self.encrypt_key) < MIN_KEY_BYTES:
                raise ValueError(f"encrypt_key must be at least {MIN_KEY_BYTES} bytes")
        if self.mode is RedactionMode.FICTIONALIZE and not self.hmac_key:
            raise ValueError("fictionalize mode requires an hmac_key")
        if not self.mask_char:
            # an empty mask char would delete the masked span instead of hiding
            # it, silently changing the output length and shape
            raise ValueError("mask_char must be a non-empty string")
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
            n = len(detection.text)
            # Never reveal more than half the value: with a fixed keep_last a
            # short entity (a 3-letter name, a 4-digit PIN) would otherwise be
            # rendered entirely unmasked — a redaction that redacts nothing.
            keep = min(max(0, self.mask_keep_last), n // 2)
            visible = detection.text[n - keep :] if keep else ""
            return self.mask_char * (n - keep) + visible
        if self.mode is RedactionMode.PSEUDONYMIZE:
            assert isinstance(self.hmac_key, bytes)
            digest = hmac.new(self.hmac_key, detection.text.encode(), hashlib.sha256)
            token = digest.hexdigest()[: self.pseudonym_length]
            return f"<{detection.entity_type.value.upper()}_{token}>"
        kind, text = detection.entity_type.value, detection.text
        if self.mode is RedactionMode.HASH:
            salt = self.hash_salt if isinstance(self.hash_salt, bytes) else b""
            return hash_token(self.hash_algorithm, salt, kind, text, self.pseudonym_length)
        if self.mode is RedactionMode.ENCRYPT:
            assert isinstance(self.encrypt_key, bytes)
            return encrypt_token(self.encrypt_key, kind, text)
        if self.mode is RedactionMode.FICTIONALIZE:
            assert isinstance(self.hmac_key, bytes)
            return fictionalize(self.hmac_key, kind, text)
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
