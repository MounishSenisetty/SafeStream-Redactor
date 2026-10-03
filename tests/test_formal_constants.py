"""Guards the audited locality constants in docs/FORMAL_MODEL.md against drift.

The formal equivalence guarantee (Theorem 1) rests on three constants that the
paper claims are *read from the implementation*: ``L_max`` (bounded span, A1) and
``C_left`` / ``C_right`` (bounded context, A2). Those constants were originally
hand-traced from the base pipeline. New default-on tiers (the label-anchored
identifier cascade) widened the pipeline's context window, so the hand-traced
values can silently go stale — exactly the kind of gap that undermines a
"constants audited from code" claim.

This test derives the constants mechanically from the ``StreamingRequirements``
the active detectors declare, pins the documented values, and asserts the
theorem's premise (``overlap >= max(L_max, C_left, C_right)``) actually holds for
the shipped configuration. If a future detector reads more context than the
documented constant, this test fails and forces docs/FORMAL_MODEL.md (and the
paper) to be corrected in lockstep.
"""

from __future__ import annotations

from safestream_redactor.detectors.base import requirements_of
from safestream_redactor.engine import DEFAULT_OVERLAP, required_overlap
from safestream_redactor.redactor import Redactor

# The constants documented in docs/FORMAL_MODEL.md section 3 for the DEFAULT
# pipeline. C_left is set by the label-anchored cascade's cue window (96), not by
# the contextual scorer (48); C_right is that cascade's declared trailing reach
# (8); L_max is the default overlap. Keep these three in sync with the doc.
DOC_C_LEFT = 96
DOC_C_RIGHT = 128  # structured-field tier (Phase 1); was 8
DOC_L_MAX = 8 * 1024


def _constants(redactor: Redactor) -> tuple[int, int, int]:
    """(L_max, C_left, C_right) derived from a redactor's active detectors."""
    reqs = [requirements_of(d) for d in redactor._detectors]
    l_max = max(r.max_span for r in reqs)
    c_left = max(r.left_context for r in reqs)
    c_right = max(r.right_context for r in reqs)
    return l_max, c_left, c_right


def test_default_pipeline_constants_match_the_documented_values() -> None:
    l_max, c_left, c_right = _constants(Redactor())
    assert (l_max, c_left, c_right) == (DOC_L_MAX, DOC_C_LEFT, DOC_C_RIGHT), (
        "audited locality constants drifted from docs/FORMAL_MODEL.md; update the "
        f"doc and paper: derived (L_max, C_left, C_right)=({l_max}, {c_left}, {c_right})"
    )


def test_theorem1_premise_holds_at_default_overlap() -> None:
    # w >= max(L_max, C_left, C_right) is the premise of Theorem 1.
    l_max, c_left, c_right = _constants(Redactor())
    assert max(l_max, c_left, c_right) <= DEFAULT_OVERLAP
    assert Redactor().min_safe_overlap == DEFAULT_OVERLAP


def test_optional_semantic_tiers_stay_within_the_overlap() -> None:
    # Opt-in tiers (ensemble) read wider context than the base tiers, but must
    # still fit inside the default overlap or streaming equivalence would break.
    r = Redactor(use_ensemble=True, use_gazetteer=True)
    l_max, c_left, c_right = _constants(r)
    assert max(l_max, c_left, c_right) <= DEFAULT_OVERLAP
    assert required_overlap(r._detectors) <= DEFAULT_OVERLAP


def test_c_left_is_driven_by_the_labeled_identifier_cascade() -> None:
    # Documents *why* C_left is 96 and not 48: it is the cascade's cue->value
    # window, not the contextual scorer (which reads only 48). With the cascade
    # out of scope, no default detector reads as far left, so C_left drops.
    from safestream_redactor.detectors.contextual import ContextualScorer
    from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector

    assert LabeledIdentifierDetector().requirements.left_context == DOC_C_LEFT
    assert ContextualScorer().requirements.left_context == 48

    without_cascade = Redactor(types=["email"])  # no SSN/PHONE/... -> no cascade
    assert "labeled_identifier" not in without_cascade.detector_names
    _, c_left, _ = _constants(without_cascade)
    assert c_left < DOC_C_LEFT
