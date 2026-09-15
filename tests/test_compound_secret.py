"""Regression suite for the compound (symbol-containing) secret tier.

Covers the documented cause-#4 gap (``benchmarks/redactionbench/AUDIT.md``): a
high-entropy secret with an embedded strong special that the base entropy
candidate splits on and misses. The tier must close that gap while keeping the
precision that makes SafeStream's secret detection its differentiator — no new
false positives on prose, URLs, hosts, e-mail addresses, file paths, hashes, or
base64 — and must preserve the streaming/parallel equivalence guarantees.
"""

from __future__ import annotations

import pytest

from safestream_redactor.detectors.entropy import (
    MAX_SPAN,
    CompoundSecretDetector,
    EntropyDetector,
)
from safestream_redactor.entities import EntityType
from safestream_redactor.redactor import Redactor

# --- the gap this tier exists to close -------------------------------------

COMPOUND_SECRETS = [
    "devPass_pP0p18yO3n!vT8wZ",
    "8Kf3-Lp9x_Qz2!vB7nR4wT",
    "Hunter2!SummerBreeze#42x",
    "Str0ng-P4ss!word_2024xZq",
]


@pytest.mark.parametrize("secret", COMPOUND_SECRETS)
def test_compound_secret_is_detected(secret: str) -> None:
    dets = CompoundSecretDetector().detect(f"the value {secret} was set")
    assert any(d.text == secret and d.entity_type is EntityType.SECRET for d in dets), (
        f"{secret!r} not detected"
    )


@pytest.mark.parametrize("secret", COMPOUND_SECRETS)
def test_base_entropy_tier_misses_these(secret: str) -> None:
    # Confirms the tier is closing a real gap, not duplicating the entropy tier:
    # the base candidate splits on the strong special and misses the whole span.
    dets = EntropyDetector().detect(f"the value {secret} was set")
    assert not any(d.text == secret for d in dets)


@pytest.mark.parametrize("secret", COMPOUND_SECRETS)
def test_detected_through_default_pipeline(secret: str) -> None:
    dets = Redactor().detect(f"the value {secret} was set")
    assert any(secret in d.text for d in dets)


# --- precision guards: none of these may become a secret -------------------

BENIGN = [
    "visit https://api.example.com/v1/users?id=42&sort=name today",
    "the host is hunter2secret@db.internal for now",
    "email me at john.doe+tag@example.co.uk please",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "path /usr/local/lib/python3.11/site-packages/foo/bar.py",
    "css .btn--primary{color:#fff!important;margin:0;padding:0}",
    "assert x!=y and foo.bar_baz==qux for the loop",
    "func(a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10)",
    "base64 aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=",
    "just some ordinary! prose? with. punctuation, nothing secret",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_produces_no_compound_secret(text: str) -> None:
    assert CompoundSecretDetector().detect(text) == []


def test_requires_embedded_strong_special() -> None:
    # A base64 char (+ / = _ -) does NOT count as the secret-indicating gate.
    d = CompoundSecretDetector()
    assert (
        d.detect("aB3xK9pLmQ2rT7vY4wZ8nC1dE5fG6") == []
    )  # no strong special -> entropy tier's job
    assert d.detect("aB3xK9pLmQ2rT7!vY4wZ8nC1dE5")  # same but with an embedded '!'


def test_strong_special_at_edges_is_not_enough() -> None:
    # A leading/trailing '!' (prose emphasis) must not qualify a run.
    assert CompoundSecretDetector().detect("Congratulations everybody wonderful!") == []


def test_short_runs_are_ignored() -> None:
    assert CompoundSecretDetector().detect("ab!Cd1") == []


def test_repeated_filler_is_rejected() -> None:
    # High-special but low distinct-character ratio: padded filler, not a secret.
    assert CompoundSecretDetector().detect("aaaaaa!aaaaaa#aaaaaa*aaaaaa") == []


# --- span bound / streaming safety -----------------------------------------


def test_span_never_exceeds_max_span() -> None:
    req = CompoundSecretDetector().requirements
    assert req.max_span == MAX_SPAN  # keeps A1 (docs/FORMAL_MODEL.md) unchanged
    long = "aB3!" * (MAX_SPAN // 2)  # a run far longer than MAX_SPAN
    for det in CompoundSecretDetector().detect(long):
        assert det.end - det.start <= MAX_SPAN


def test_streaming_matches_whole_document() -> None:
    r = Redactor()
    text = (
        "Line one, nothing here. The rotated password is devPass_pP0p18yO3n!vT8wZ "
        "and the backup token 8Kf3-Lp9x_Qz2!vB7nR4wT is stored. Prose! Ends here.\n"
    ) * 4
    whole = r.redact(text)
    for chunk_size in (1, 3, 7, 13, 64, 8192):
        streamed = "".join(
            r.redact_stream(text[i : i + chunk_size] for i in range(0, len(text), chunk_size))
        )
        assert streamed == whole, f"streaming diverged at chunk_size={chunk_size}"


def test_disabling_entropy_disables_compound_tier() -> None:
    assert "compound_secret" not in Redactor(use_entropy=False).detector_names
    assert "compound_secret" in Redactor().detector_names


def test_prefilter_skips_input_without_strong_special() -> None:
    # A window with no strong special (! # $ % ^ & * ~) cannot contain a compound
    # secret, so the detector short-circuits and returns [] without scanning. This
    # keeps the tier near-free on large secret-sparse blobs (e.g. base64/alpha runs)
    # and is detection-neutral: a strong special is a necessary condition.
    assert CompoundSecretDetector().detect("A" * 200_000) == []
    assert CompoundSecretDetector().detect("base64 " + "aGVsbG8" * 5000) == []
    # a strong special still triggers full detection
    assert CompoundSecretDetector().detect("the value Hunter2!SummerBreeze#42x here")
