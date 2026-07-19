"""Core data types shared by every tier of the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    """Kinds of sensitive entities SafeStream can detect."""

    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"
    API_KEY = "api_key"
    JWT = "jwt"
    PRIVATE_KEY = "private_key"
    # NER tier
    PERSON = "person"
    ORG = "org"
    LOC = "loc"
    # user-supplied words / regexes
    CUSTOM = "custom"

    @classmethod
    def from_name(cls, name: str) -> EntityType:
        try:
            return cls(name.strip().lower())
        except ValueError:
            valid = ", ".join(e.value for e in cls)
            raise ValueError(f"unknown entity type {name!r}; valid types: {valid}") from None


@dataclass(slots=True)
class Detection:
    """A single sensitive span found in text.

    Offsets are relative to the text passed to the detector. The streaming
    engine translates them as its window slides, so user code only ever sees
    offsets into the text it supplied.
    """

    start: int
    end: int
    text: str
    entity_type: EntityType
    confidence: float
    source: str = "deterministic"
    meta: dict[str, str] = field(default_factory=dict)

    def overlaps(self, other: Detection) -> bool:
        return self.start < other.end and other.start < self.end


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Keep at most one detection per region of text.

    On overlap the higher-confidence detection wins; ties go to the longer
    span (a credit card should beat the phone number hiding inside it).
    """
    import bisect

    ordered = sorted(detections, key=lambda d: (-d.confidence, d.start - d.end, d.start))
    # kept intervals stay sorted by start and never overlap each other, so a
    # candidate can only collide with the interval just before its end point
    starts: list[int] = []
    kept: list[Detection] = []
    for cand in ordered:
        i = bisect.bisect_left(starts, cand.end)
        if i > 0 and kept[i - 1].end > cand.start:
            continue
        starts.insert(i, cand.start)
        kept.insert(i, cand)
    return kept
