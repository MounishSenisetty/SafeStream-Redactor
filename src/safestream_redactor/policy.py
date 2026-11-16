"""Redaction policies: how a detected span is rewritten."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum

from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.errors import OperatorError
from safestream_redactor.operators import (
    HASH_ALGORITHMS,
    MIN_KEY_BYTES,
    encrypt_token,
    fictionalize,
    hash_token,
    require_crypto,
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


# Types whose last few characters may stay visible in mask mode: numbers people
# recognise by their tail ("card ending 1111"). A secret, name, email or address
# is masked in full: any visible part of a password or a name is a leak.
_MASK_TAIL_TYPES = frozenset(
    {
        EntityType.CREDIT_CARD,
        EntityType.PHONE,
        EntityType.SSN,
        EntityType.ID_NUMBER,
        EntityType.IBAN,
        EntityType.IN_AADHAAR,
        EntityType.NHS_NUMBER,
    }
)
# At most this many letters/digits of a tail are shown, whatever keep_last says
# (PCI DSS allows the last four digits of a card number).
_MASK_MAX_TAIL = 4


def _mask_keep(detection: Detection, keep_last: int) -> int:
    """How many trailing characters of ``detection`` mask mode leaves visible."""
    if detection.entity_type not in _MASK_TAIL_TYPES:
        return 0
    text = detection.text
    # never more than half the value, so a short value is never shown in full
    limit = min(max(0, keep_last), len(text) // 2)
    keep = shown = 0
    while keep < limit and shown < _MASK_MAX_TAIL:
        keep += 1
        shown += text[-keep].isalnum()
    return keep


def _canonical(detection: Detection) -> str:
    """The form a value is pseudonymised by: equal values must get equal tokens.

    An email address is case-insensitive in practice, so ``Bob@X.io`` and
    ``bob@x.io`` (the same mailbox) map to one pseudonym and stay linkable.
    """
    if detection.entity_type is EntityType.EMAIL:
        return detection.text.lower()
    return detection.text


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
    hmac_key: bytes | str | None = field(default=None, repr=False)
    # Hex digits kept from the HMAC in pseudonymize mode. 16 hex = 64 bits,
    # which pushes the birthday-collision point past ~4 billion distinct
    # values; the old 10-hex (40-bit) default collided around ~1 million,
    # realistic for a large log with many distinct secrets. Minimum 8.
    pseudonym_length: int = 16
    # HASH mode: digest algorithm and an optional secret salt.
    hash_algorithm: str = "sha256"
    hash_salt: bytes | str | None = field(default=None, repr=False)
    # ENCRYPT mode: secret key (>= 16 bytes; text keys are UTF-8 encoded).
    encrypt_key: bytes | str | None = field(default=None, repr=False)

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
                raise OperatorError("encrypt mode requires an encrypt_key")
            if len(self.encrypt_key) < MIN_KEY_BYTES:
                raise OperatorError(f"encrypt_key must be at least {MIN_KEY_BYTES} bytes")
            require_crypto()  # fail now, not on the first match mid-stream
        if self.mode is RedactionMode.FICTIONALIZE and not self.hmac_key:
            raise ValueError("fictionalize mode requires an hmac_key")
        if len(self.mask_char) != 1:
            # an empty mask char would delete the masked span instead of hiding
            # it, and a longer one would change the output length and shape
            raise ValueError("mask_char must be a single character")
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
            keep = _mask_keep(detection, self.mask_keep_last)
            visible = detection.text[n - keep :] if keep else ""
            return self.mask_char * (n - keep) + visible
        if self.mode is RedactionMode.PSEUDONYMIZE:
            assert isinstance(self.hmac_key, bytes)
            digest = hmac.new(self.hmac_key, _canonical(detection).encode(), hashlib.sha256)
            token = digest.hexdigest()[: self.pseudonym_length]
            return f"<{detection.entity_type.value.upper()}_{token}>"
        kind, text = detection.entity_type.value, detection.text
        if self.mode is RedactionMode.HASH:
            salt = self.hash_salt if isinstance(self.hash_salt, bytes) else b""
            return hash_token(
                self.hash_algorithm, salt, kind, _canonical(detection), self.pseudonym_length
            )
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
