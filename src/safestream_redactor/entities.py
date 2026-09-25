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
    # AWS Secret Access Key (the 40-char secret paired with an access key id)
    AWS_SECRET = "aws_secret"
    GITHUB_TOKEN = "github_token"
    API_KEY = "api_key"
    JWT = "jwt"
    PRIVATE_KEY = "private_key"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    STRIPE_KEY = "stripe_key"
    GOOGLE_API_KEY = "google_api_key"
    SENDGRID_KEY = "sendgrid_key"
    TWILIO_KEY = "twilio_key"
    NPM_TOKEN = "npm_token"
    OPENAI_KEY = "openai_key"
    ANTHROPIC_KEY = "anthropic_key"
    # password embedded in a connection-string / URL userinfo section
    URL_CREDENTIALS = "url_credentials"
    # generic high-entropy secret (no published format)
    SECRET = "secret"
    # NER tier
    PERSON = "person"
    ORG = "org"
    LOC = "loc"
    # date of birth (label-anchored)
    DOB = "dob"
    # generic sensitive identifier caught only via an adjacent label cue
    # (student/employee/member/patient/account/MRN/licence/passport/... numbers)
    ID_NUMBER = "id_number"
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
    # Process candidates best-first; a candidate is kept only if it overlaps
    # nothing already kept (equivalently, no higher-priority detection covers
    # it). Kept spans are collected in priority order and sorted by start once at
    # the end, avoiding the O(n) mid-list insertions the previous parallel-array
    # bookkeeping performed on every candidate.
    ordered = sorted(detections, key=lambda d: (-d.confidence, d.start - d.end, d.start))
    kept: list[Detection] = []
    for cand in ordered:
        if not any(cand.overlaps(k) for k in kept):
            kept.append(cand)
    kept.sort(key=lambda d: d.start)
    return kept
