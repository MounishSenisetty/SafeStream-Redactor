"""Core data types shared by every tier of the pipeline."""

from __future__ import annotations

from bisect import bisect_left, insort
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
    # hardware (EUI-48/EUI-64) address: a stable device identifier
    MAC_ADDRESS = "mac_address"
    AWS_KEY = "aws_key"
    # 12-digit AWS account id, only where an ARN / AWS endpoint frames it
    AWS_ACCOUNT_ID = "aws_account_id"
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
    # a prefixed token from a vendor without its own type (Atlassian, Doppler,
    # Dropbox, Vault, Mapbox, Teams webhooks, Salesforce, Telegram, New Relic, Mailgun)
    VENDOR_TOKEN = "vendor_token"
    # a password hash (bcrypt, sha-crypt, md5-crypt, argon2, scrypt, PBKDF2, Kerberos)
    PASSWORD_HASH = "password_hash"
    # generic high-entropy secret (no published format)
    SECRET = "secret"
    # NER tier
    PERSON = "person"
    ORG = "org"
    LOC = "loc"
    # postal address: a street line, or "City, ST 12345" (line-bounded patterns)
    ADDRESS = "address"
    # date of birth (label-anchored)
    DOB = "dob"
    # any calendar date / time of day (opt-in: logs are full of timestamps)
    DATE = "date"
    # the value of a username/login field (field-anchored only)
    USERNAME = "username"
    # every URL (prose profile); by default only credentialed/webhook URLs and
    # the values of sensitive query parameters are redacted
    URL = "url"
    # sex/gender and honorific/job-title fields (prose profile only)
    SEX = "sex"
    TITLE = "title"
    # nationality / religious-group words (prose profile only)
    NRP = "nrp"
    # generic sensitive identifier caught only via an adjacent label cue
    # (student/employee/member/patient/account/MRN/licence/passport/... numbers)
    ID_NUMBER = "id_number"
    # regional / checksum-validated identifiers (opt-in tier: detectors/regional.py)
    IBAN = "iban"
    CRYPTO_ADDRESS = "crypto_address"
    UK_NINO = "uk_nino"
    NHS_NUMBER = "nhs_number"
    IN_AADHAAR = "in_aadhaar"
    IN_PAN = "in_pan"
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


#: Sources of the statistical name tiers (spaCy, ONNX, gazetteer, ensemble). Every
#: other source -- the deterministic/entropy/checksum tiers, custom rules and plugins --
#: is "Tier 0" and takes precedence over these in :func:`resolve_overlaps`.
NER_SOURCES = frozenset({"ner", "onnx", "gazetteer_name", "semantic_ensemble"})


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Keep at most one detection per region of text.

    Tier-0 detections resolve among themselves: on overlap the higher-confidence
    one wins; ties go to the longer span (a credit card should beat the phone
    number hiding inside it). NER detections (:data:`NER_SOURCES`) never drop
    one another or a Tier-0 span: every cluster of overlapping spans that holds
    an NER span becomes one span covering the whole cluster, labelled by its
    best Tier-0 member (or, with none, its best NER member). Dropping either side
    would leave the other's uncovered characters in the clear: a PERSON tag on
    ``john.doe`` must not leave ``@example.com`` of the email exposed, and a
    PERSON "Priya" must not beat an ORG "Priya Iyer" and leave "Iyer" exposed.
    """
    ner = [d for d in detections if d.source in NER_SOURCES]
    if not ner:
        return _greedy(detections)
    tier0 = _greedy([d for d in detections if d.source not in NER_SOURCES])
    merged: list[Detection] = []
    cluster: list[Detection] = []
    cluster_end = 0
    for det in sorted(tier0 + ner, key=lambda d: d.start):
        if cluster and det.start >= cluster_end:
            merged.append(_union(cluster))
            cluster = []
        cluster.append(det)
        cluster_end = max(cluster_end, det.end) if len(cluster) > 1 else det.end
    if cluster:
        merged.append(_union(cluster))
    return merged


def _union(cluster: list[Detection]) -> Detection:
    """One span over a start-sorted run of overlapping detections."""
    if len(cluster) == 1:
        return cluster[0]
    # Tier-0 spans were made non-overlapping, so a cluster of 2+ holds an NER
    # span; a Tier-0 member, when there is one, names the merged span
    tier0 = [d for d in cluster if d.source not in NER_SOURCES]
    best = max(tier0 or cluster, key=lambda d: (d.confidence, d.end - d.start))
    text, end = cluster[0].text, cluster[0].end
    for det in cluster[1:]:
        if det.end > end:  # overlapping, so the new tail starts inside text
            text += det.text[end - det.start :]
            end = det.end
    return Detection(
        start=cluster[0].start,
        end=end,
        text=text,
        entity_type=best.entity_type,
        confidence=best.confidence,
        source=best.source,
        meta=dict(best.meta),
    )


def _greedy(detections: list[Detection]) -> list[Detection]:
    """Best-first selection of pairwise non-overlapping detections."""
    # Process candidates best-first; a candidate is kept only if it overlaps
    # nothing already kept (equivalently, no higher-priority detection covers
    # it). The kept spans are pairwise non-overlapping, so ordered by
    # (start, end) their ends are non-decreasing too; the only kept span that can
    # overlap a candidate [s, e) is therefore the last one starting before e. One
    # bisection per candidate replaces the linear scan over everything kept,
    # making this O(n log n) instead of O(n^2) on detection-dense windows.
    ordered = sorted(detections, key=lambda d: (-d.confidence, d.start - d.end, d.start))
    kept: list[Detection] = []
    spans: list[tuple[int, int]] = []  # kept (start, end), sorted
    for cand in ordered:
        i = bisect_left(spans, (cand.end,))
        if i and spans[i - 1][1] > cand.start:
            continue
        insort(spans, (cand.start, cand.end))
        kept.append(cand)
    kept.sort(key=lambda d: d.start)
    return kept
