"""Detector streaming-requirements metadata drives the engine's overlap."""

from __future__ import annotations

import logging

from safestream_redactor import Redactor
from safestream_redactor.detectors.base import (
    StreamingRequirements,
    requirements_of,
)
from safestream_redactor.detectors.contextual import ContextualScorer
from safestream_redactor.detectors.deterministic import DeterministicDetector
from safestream_redactor.detectors.entropy import EntropyDetector
from safestream_redactor.engine import DEFAULT_OVERLAP, required_overlap
from safestream_redactor.entities import Detection, EntityType


def test_requirements_required_overlap_math() -> None:
    req = StreamingRequirements(max_span=100, right_context=20, left_context=200)
    # max(span + right, left) = max(120, 200) = 200
    assert req.required_overlap == 200


def test_builtin_detectors_declare_requirements() -> None:
    assert DeterministicDetector().requirements.max_span == 8 * 1024
    assert EntropyDetector().requirements.max_span == 8 * 1024
    ctx = ContextualScorer().requirements
    assert ctx.max_span == 9
    assert ctx.left_context == 48


def test_requirements_of_falls_back_for_undeclared() -> None:
    class Bare:
        name = "bare"

        def detect(self, text: str) -> list[Detection]:
            return []

    # A detector with no `requirements` attribute gets the conservative default,
    # preserving the historical overlap for third-party detectors.
    assert requirements_of(Bare()).max_span == DEFAULT_OVERLAP


def test_engine_required_overlap_is_max_across_detectors() -> None:
    detectors = [DeterministicDetector(), EntropyDetector(), ContextualScorer()]
    assert required_overlap(detectors) == 8 * 1024


def test_redactor_min_safe_overlap_matches_default() -> None:
    # The default configuration's derived overlap equals the historical constant,
    # so nothing about default behaviour changes.
    assert Redactor().min_safe_overlap == DEFAULT_OVERLAP


def test_shrinking_overlap_below_requirement_is_rejected() -> None:
    # Fail-closed by default: an unsafe overlap raises rather than silently
    # risking a boundary-induced redaction leak (privacy tool).
    import pytest

    with pytest.raises(ValueError, match="safe minimum"):
        Redactor(overlap=16)


def test_unsafe_overlap_opt_in_warns_instead_of_raising(caplog) -> None:
    # The explicit escape hatch downgrades the error to a warning.
    with caplog.at_level(logging.WARNING, logger="safestream_redactor.redactor"):
        Redactor(overlap=16, allow_unsafe_overlap=True)
    assert any("below" in rec.message for rec in caplog.records)


def test_default_overlap_does_not_warn(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="safestream_redactor.redactor"):
        Redactor()
    assert not [r for r in caplog.records if "below" in r.message]


def test_custom_detector_with_small_requirement_lowers_needed_overlap() -> None:
    # A redactor restricted to a single short-span detector needs less overlap.
    class ShortDetector:
        name = "short"
        requirements = StreamingRequirements(max_span=16)

        def detect(self, text: str) -> list[Detection]:
            return []

    r = Redactor(
        types=[EntityType.EMAIL],
        use_entropy=False,
        extra_detectors=[ShortDetector()],
        load_plugins=False,
    )
    # deterministic email still declares 8192, so the max is still 8192 — the
    # aggregate is the *max*, never lowered by adding a smaller detector.
    assert r.min_safe_overlap == 8 * 1024
    # but a lone short detector on its own would need only 16
    assert required_overlap([ShortDetector()]) == 16
