"""Bridge between RedactionBench records and the SafeStream-Redactor pipeline.

The adapter exercises the **real production pipeline** — the same
:class:`safestream_redactor.Redactor` a user gets from ``pip install`` — in one
of two modes:

* ``streaming`` (default): the document is fed to
  :meth:`Redactor.detect_stream` as fixed-size chunks, i.e. the constant-memory
  rolling-buffer engine that is SafeStream's headline architecture. Segment-local
  detection offsets are translated back to absolute document offsets here, so a
  detection is scored at its true position even when it straddled a chunk
  boundary. This is the mode that actually tests chunk-boundary handling.
* ``whole``: the document is passed to :meth:`Redactor.detect` in one piece.
  Useful as a cross-check that streaming and whole-document detection agree.

A prediction is ``(start, end, safestream_type, confidence)``. The harness never
reaches into detector internals; it only calls the public ``detect``/
``detect_stream`` API and reads the returned :class:`Detection` objects.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from safestream_redactor import Redactor
from safestream_redactor.engine import DEFAULT_CHUNK_SIZE


@dataclass(frozen=True)
class Prediction:
    start: int
    end: int
    label: str  # SafeStream entity-type value, e.g. "email"
    confidence: float
    source: str = ""  # detector tier that produced it


def _chunks(text: str, chunk_size: int) -> Iterator[str]:
    for i in range(0, len(text), chunk_size):
        yield text[i : i + chunk_size]


def predict_streaming(
    redactor: Redactor, text: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> list[Prediction]:
    """Predictions from the constant-memory streaming engine, absolute offsets.

    ``detect_stream`` yields ``(segment, detections)`` where each segment's
    detections carry segment-relative offsets and the segments concatenate to
    the full input in order. We accumulate the emitted length to lift every
    detection back into document coordinates.
    """
    preds: list[Prediction] = []
    base = 0
    for segment, detections in redactor.detect_stream(_chunks(text, chunk_size)):
        for d in detections:
            preds.append(
                Prediction(
                    start=base + d.start,
                    end=base + d.end,
                    label=d.entity_type.value,
                    confidence=float(d.confidence),
                    source=d.source,
                )
            )
        base += len(segment)
    # Sanity: the segments must reconstruct the input exactly, or offsets are off.
    if base != len(text):  # pragma: no cover - guards against engine contract drift
        raise RuntimeError(
            f"streaming segments summed to {base} chars but the document is {len(text)}; "
            "absolute-offset reconstruction would be wrong"
        )
    return preds


def predict_whole(redactor: Redactor, text: str) -> list[Prediction]:
    """Predictions from whole-document detection (no chunking)."""
    return [
        Prediction(
            start=d.start,
            end=d.end,
            label=d.entity_type.value,
            confidence=float(d.confidence),
            source=d.source,
        )
        for d in redactor.detect(text)
    ]


def predict(
    redactor: Redactor, text: str, mode: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> list[Prediction]:
    if mode == "streaming":
        return predict_streaming(redactor, text, chunk_size)
    if mode == "whole":
        return predict_whole(redactor, text)
    raise ValueError(f"unknown prediction mode {mode!r} (use 'streaming' or 'whole')")


# ---------------------------------------------------------------------------
# label mapping: RedactionBench category names -> SafeStream entity types
# ---------------------------------------------------------------------------

# SafeStream's detectable entity-type *values* (from entities.EntityType). Used
# to validate a mapping and to report which dataset categories are unsupported.
from safestream_redactor.entities import EntityType  # noqa: E402

SAFESTREAM_TYPES: frozenset[str] = frozenset(e.value for e in EntityType)

# A best-effort default mapping from common RedactionBench / PII-corpus category
# labels onto SafeStream entity types. It is intentionally conservative: only
# categories SafeStream can actually detect are mapped. Everything unmapped is
# reported as an "unsupported category" rather than silently scored as a miss
# against a type the tool never claims to find. Override or extend on the CLI
# with --label-map once the true category vocabulary is known from `inspect`.
DEFAULT_LABEL_MAP: dict[str, str] = {
    # email
    "email": "email",
    "email_address": "email",
    "e-mail": "email",
    # phone
    "phone": "phone",
    "phone_number": "phone",
    "telephone": "phone",
    "us_phone_number": "phone",
    "mobile": "phone",
    # ssn / national id
    "ssn": "ssn",
    "us_ssn": "ssn",
    "social_security_number": "ssn",
    # credit card
    "credit_card": "credit_card",
    "credit_card_number": "credit_card",
    "creditcardnumber": "credit_card",
    "card_number": "credit_card",
    # ip
    "ip": "ipv4",
    "ip_address": "ipv4",
    "ipv4": "ipv4",
    "ipv4_address": "ipv4",
    "ipv6": "ipv6",
    "ipv6_address": "ipv6",
    # names / org / location (need the NER tier to be detected)
    "person": "person",
    "name": "person",
    "person_name": "person",
    "full_name": "person",
    "firstname": "person",
    "lastname": "person",
    "org": "org",
    "organization": "org",
    "company": "org",
    "location": "loc",
    "loc": "loc",
    "address": "loc",
    "gpe": "loc",
    # credentials / secrets
    "api_key": "api_key",
    "apikey": "api_key",
    "aws_key": "aws_key",
    "aws_access_key": "aws_key",
    "aws_secret": "aws_secret",
    "github_token": "github_token",
    "jwt": "jwt",
    "private_key": "private_key",
    "slack_token": "slack_token",
    "stripe_key": "stripe_key",
    "google_api_key": "google_api_key",
    "sendgrid_key": "sendgrid_key",
    "twilio_key": "twilio_key",
    "npm_token": "npm_token",
    "openai_key": "openai_key",
    "anthropic_key": "anthropic_key",
    "secret": "secret",
    "password": "secret",
    "url_credentials": "url_credentials",
}


def normalise_label(label: str) -> str:
    return label.strip().lower().replace(" ", "_").replace("-", "_")


def build_label_map(overrides: dict[str, str] | None) -> dict[str, str]:
    """Merge user overrides onto the default mapping (keys normalised)."""
    merged = {normalise_label(k): v for k, v in DEFAULT_LABEL_MAP.items()}
    if overrides:
        for k, v in overrides.items():
            merged[normalise_label(k)] = v
    return merged


def map_gold_label(label: str, label_map: dict[str, str]) -> str | None:
    """Map a dataset category to a SafeStream type, or None if unsupported."""
    return label_map.get(normalise_label(label))
