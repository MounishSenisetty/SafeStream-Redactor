"""Tier 1: regex patterns plus validation functions.

Every pattern is paired with an optional validator so that a syntactic match
alone is not enough — e.g. credit cards must pass the Luhn checksum and IPv6
candidates must parse with :mod:`ipaddress`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from safestream_redactor.entities import Detection, EntityType

# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------


def luhn_ok(number: str) -> bool:
    """Luhn checksum used by all major card networks."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_ok(match_text: str) -> bool:
    """Reject SSNs with impossible area/group/serial numbers."""
    area, group, serial = re.split(r"[-\s]", match_text)
    if area in {"000", "666"} or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def phone_ok(match_text: str) -> bool:
    digits = re.sub(r"\D", "", match_text)
    return 7 <= len(digits) <= 15


def ipv6_ok(match_text: str) -> bool:
    try:
        ipaddress.IPv6Address(match_text.split("%")[0])
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pattern:
    entity_type: EntityType
    regex: re.Pattern[str]
    confidence: float
    validator: Callable[[str], bool] | None = None
    group: int = 0  # capture group whose span becomes the detection


_PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        EntityType.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
    ),
    Pattern(
        EntityType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"[A-Za-z0-9+/=\s]+?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        0.99,
    ),
    Pattern(
        EntityType.JWT,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        0.95,
    ),
    Pattern(
        EntityType.AWS_KEY,
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        0.98,
    ),
    Pattern(
        EntityType.GITHUB_TOKEN,
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        0.98,
    ),
    Pattern(
        EntityType.API_KEY,
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token"
            r"|token|password|passwd|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{12,128})[\"']?"
        ),
        0.75,
        group=1,
    ),
    Pattern(
        EntityType.CREDIT_CARD,
        re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        0.9,
        validator=luhn_ok,
    ),
    Pattern(
        EntityType.SSN,
        re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
        0.85,
        validator=ssn_ok,
    ),
    Pattern(
        EntityType.IPV4,
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
        ),
        0.9,
    ),
    Pattern(
        EntityType.IPV6,
        # loose candidate (hex groups separated by >=2 colons); ipaddress validates
        re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])"),
        0.9,
        validator=ipv6_ok,
    ),
    Pattern(
        EntityType.PHONE,
        re.compile(
            r"(?<![\w.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]?\d{2,4}){1,4}"
            r"(?![\w-])(?!\.\d)"
        ),
        0.6,
        validator=phone_ok,
    ),
)


class DeterministicDetector:
    """Runs the built-in regex+validator patterns, optionally a subset of types."""

    name = "deterministic"

    def __init__(self, types: Iterable[EntityType] | None = None) -> None:
        wanted = set(types) if types is not None else None
        self._patterns = [p for p in _PATTERNS if wanted is None or p.entity_type in wanted]

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for pattern in self._patterns:
            for m in pattern.regex.finditer(text):
                matched = m.group(pattern.group)
                if pattern.validator is not None and not pattern.validator(matched):
                    continue
                found.append(
                    Detection(
                        start=m.start(pattern.group),
                        end=m.end(pattern.group),
                        text=matched,
                        entity_type=pattern.entity_type,
                        confidence=pattern.confidence,
                        source=self.name,
                    )
                )
        return found
