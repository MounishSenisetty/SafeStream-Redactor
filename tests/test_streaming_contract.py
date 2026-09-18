"""Enforces that every detector's *declared* streaming contract is >= its *actual*
context dependency, and that the configured semantic-ensemble pipeline is
byte-equivalent under streaming — the class of bug the hostile review found.

Background
----------
The streaming-equivalence guarantee (docs/FORMAL_MODEL.md, Theorem 1) is sound
only if each detector's declared ``StreamingRequirements`` is a true upper bound
on the context it actually reads. The ``SemanticEnsembleDetector`` previously
declared ``left_context=96`` while its repeated-mention signal looked back
``propagation_window=2048``, so ``required_overlap()`` reported an unsafe overlap
(112) as safe and streaming could leak a name a whole-document pass redacted.

These tests pin the fix so it cannot regress:
 * (A) declared left_context tracks the real propagation window,
 * (D) the production API refuses an unsafe overlap by default,
 * (E) the previously-leaking repeated-mention case is reproduced and fixed,
 * (F) every built-in detector declares a max_span that bounds what it emits,
 * (B/C) randomized-chunking equivalence with the ensemble enabled.
"""

from __future__ import annotations

import itertools
import random

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.base import requirements_of
from safestream_redactor.detectors.contextual import ContextualScorer
from safestream_redactor.detectors.deterministic import DeterministicDetector
from safestream_redactor.detectors.entropy import CompoundSecretDetector, EntropyDetector
from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector
from safestream_redactor.detectors.semantic_ensemble import SemanticEnsembleDetector
from safestream_redactor.engine import required_overlap, stream_windows


def _chunks(text: str, cuts: list[int]):
    cuts = [0, *sorted(c for c in cuts if 0 < c < len(text)), len(text)]
    return [text[a:b] for a, b in itertools.pairwise(cuts)]


def _stream_dets(detector, text: str, overlap: int, cuts: list[int]):
    """Absolute-offset detections from streaming ``detector`` over ``cuts``."""
    out = set()
    off = 0
    for seg, dets in stream_windows(iter(_chunks(text, cuts)), detector.detect, overlap):
        for d in dets:
            out.add((off + d.start, off + d.end, d.text, d.entity_type.value))
        off += len(seg)
    return out


def _whole_dets(detector, text: str):
    return {(d.start, d.end, d.text, d.entity_type.value) for d in detector.detect(text)}


# --- (A) declared contract >= actual dependency ----------------------------


def test_ensemble_declared_left_context_tracks_propagation_window() -> None:
    # The declaration must be derived from the real state-propagation parameter,
    # not a hard-coded constant. Fails if someone bumps propagation_window (or
    # re-hard-codes left_context) without keeping the declaration truthful.
    for pw in (512, 2048, 4096):
        d = SemanticEnsembleDetector(propagation_window=pw)
        assert requirements_of(d).left_context >= pw, (pw, requirements_of(d))


def test_ensemble_declared_left_context_covers_actual_repeated_mention() -> None:
    # Empirically: a bare surname is boosted by a full name up to ~propagation
    # chars earlier. A window as wide as the *declared* left_context must
    # reproduce that verdict (declaration is sufficient), while a 96-char window
    # (the old declaration) must not (the dependency is real and far larger).
    d = SemanticEnsembleDetector(policy="strict")
    dist = d.propagation_window - 200
    # comma before the bare surname so it is a lone single-token candidate (the
    # repeated-mention path); "Later Vance" would merge into one two-token span.
    text = "Dr. Melissa Vance chaired it. " + ("x " * (dist // 2)) + "Later, Vance signed."
    bare = text.rfind("Vance")
    assert 96 < (bare - text.index("Vance")) <= d.propagation_window
    assert any(t == "Vance" and s == bare for s, _e, t, _ty in _whole_dets(d, text))

    declared = requirements_of(d).left_context
    wide = text[max(0, bare - declared) : bare + len("Vance")]
    assert any(x.text == "Vance" for x in d.detect(wide)), "declared window insufficient"
    narrow = text[max(0, bare - 96) : bare + len("Vance")]
    assert not any(x.text == "Vance" for x in d.detect(narrow)), "old 96 window would suffice?"


def test_required_overlap_for_ensemble_is_now_safe() -> None:
    ens = SemanticEnsembleDetector()
    # was 112 before the fix; must now be at least the propagation window.
    assert required_overlap([ens]) >= ens.propagation_window


# --- (F) every built-in detector's declared max_span bounds what it emits ----


def test_all_builtin_detectors_emit_within_declared_max_span() -> None:
    probe = (
        "Dr. Melissa Vance and James Wilson at Acme Institute of Technology. "
        "Email jane.doe@corp.example.com, ssn 123-45-6789, card 4111 1111 1111 1111, "
        "key AKIAIOSFODNN7EXAMPLE, secret devPass_pP0p18yO3n!vT8wZ, host 10.0.0.1, "
        "Student ID: 202184673, DOB 03/08/1996. " * 3
    )
    detectors = [
        DeterministicDetector(),
        LabeledIdentifierDetector(),
        EntropyDetector(),
        CompoundSecretDetector(),
        ContextualScorer(),
        SemanticEnsembleDetector(policy="high_recall"),
    ]
    for det in detectors:
        max_span = requirements_of(det).max_span
        for d in det.detect(probe):
            assert d.end - d.start <= max_span, f"{det.name} span {d.end - d.start} > {max_span}"


# --- (D) production API refuses an unsafe overlap by default -----------------


def test_default_pipeline_overlap_is_safe() -> None:
    r = Redactor(use_ensemble=True)  # default overlap
    assert r.overlap >= r.min_safe_overlap


def test_unsafe_overlap_rejected_with_ensemble() -> None:
    with pytest.raises(ValueError, match="safe minimum"):
        Redactor(use_ensemble=True, overlap=256)


def test_unsafe_overlap_opt_in_is_allowed() -> None:
    r = Redactor(use_ensemble=True, overlap=256, allow_unsafe_overlap=True)
    assert r.overlap == 256  # explicit opt-in honoured


# --- (E) the previously-leaking repeated-mention case -----------------------

_LEAK_TEXT = (
    "Dr. Melissa Vance reviewed the file. "
    + ("filler word here " * 40)
    + "Later, Vance approved it."
)


@pytest.mark.parametrize("overlap", [112, 256])
def test_repeated_mention_leaks_at_unsafe_overlap(overlap: int) -> None:
    # Documents WHY the overlap must be safe: below it, streaming misses the bare
    # 'Vance' that the whole-document pass redacts. The engine still runs (this is
    # the raw engine, not the guarded Redactor API), but output diverges.
    ens = SemanticEnsembleDetector(policy="strict")
    cuts = list(range(50, len(_LEAK_TEXT), 50))
    whole = _whole_dets(ens, _LEAK_TEXT)
    streamed = _stream_dets(ens, _LEAK_TEXT, overlap, cuts)
    assert any(t == "Vance" for *_x, t, _ty in whole)  # whole-doc redacts it
    assert whole != streamed  # unsafe overlap diverges (the bug)


def test_repeated_mention_safe_at_declared_overlap() -> None:
    ens = SemanticEnsembleDetector(policy="strict")
    safe = required_overlap([ens])
    cuts = list(range(37, len(_LEAK_TEXT), 37))
    assert _stream_dets(ens, _LEAK_TEXT, safe, cuts) == _whole_dets(ens, _LEAK_TEXT)


def test_isolated_ensemble_byte_identity_tiny_chunks() -> None:
    # Tiny chunks (1/2/3) and boundaries inside entities/context, exercised on the
    # ensemble alone at its own safe overlap — fast, and covers the 1-char case the
    # full-pipeline test omits for cost (deterministic forces overlap up to 8192).
    ens = SemanticEnsembleDetector(policy="high_recall")
    safe = required_overlap([ens])
    text = _CORPUS * (safe // len(_CORPUS) + 2)
    whole = _whole_dets(ens, text)
    for size in (1, 2, 3, 7):
        cuts = list(range(0, len(text), size))
        assert _stream_dets(ens, text, safe, cuts) == whole, f"size={size}"


# --- (B/C) randomized-chunking equivalence with the ensemble ENABLED ---------

_CORPUS = (
    "Dr. Melissa Vance and James Wilson met at Acme Institute of Technology.\n"
    "Contact jane.doe@corp.example.com or call +1 415 555 0100. SSN 123-45-6789.\n"
    "Card 4111 1111 1111 1111. Key AKIAIOSFODNN7EXAMPLE. Secret devPass_pP0p18yO3n!vT8wZ.\n"
    "Server 10.0.0.1. Student ID: 202184673. Later, Vance and Wilson signed off. Acme Inc.\n"
)


def _random_cutsets(n: int, length: int, seed: int) -> list[list[int]]:
    rng = random.Random(seed)
    sets = [
        list(range(0, length, 2)),  # 2-char chunks
        list(range(0, length, 3)),  # 3-char chunks
        [length // 2],
        [],  # single chunk
    ]
    for _ in range(n):
        k = rng.randint(1, 40)
        sets.append(sorted(rng.randint(0, length) for _ in range(k)))
    return sets


def test_randomized_chunking_equivalence_ensemble_strict() -> None:
    # Full pipeline incl. the ensemble, at the safe (default) overlap, over many
    # segmentations. Byte-identity of the redacted OUTPUT, not just span sets.
    r = Redactor(use_ensemble=True, semantic_policy="strict")
    # text longer than the overlap so boundary logic is genuinely exercised
    text = _CORPUS * (r.overlap // len(_CORPUS) + 2)
    whole = r.redact(text)
    for cuts in _random_cutsets(12, len(text), seed=7):
        streamed = "".join(r.redact_stream(iter(_chunks(text, cuts))))
        assert streamed == whole, f"diverged for {len(cuts)} cuts"


def test_randomized_chunking_with_empty_and_max_chunks() -> None:
    r = Redactor(use_ensemble=True, semantic_policy="high_recall")
    text = _CORPUS * (r.overlap // len(_CORPUS) + 2)
    whole = r.redact(text)
    # empty chunks interspersed, plus one maximal single chunk
    mixed = ["", text[: len(text) // 2], "", "", text[len(text) // 2 :], ""]
    assert "".join(r.redact_stream(iter(mixed))) == whole
    assert "".join(r.redact_stream(iter([text]))) == whole
    assert "".join(r.redact_stream(iter([]))) == ""


def test_overlaps_below_safe_are_rejected_at_or_above_are_accepted() -> None:
    # A redactor built with the ensemble; overlaps below the safe minimum are
    # rejected, at/above are accepted and equivalence holds.
    safe = Redactor(use_ensemble=True, allow_unsafe_overlap=True, overlap=1).min_safe_overlap
    with pytest.raises(ValueError):
        Redactor(use_ensemble=True, overlap=safe - 1)
    r = Redactor(use_ensemble=True, overlap=safe)
    text = _CORPUS * (safe // len(_CORPUS) + 2)
    whole = r.redact(text)
    for cuts in _random_cutsets(8, len(text), seed=3):
        assert "".join(r.redact_stream(iter(_chunks(text, cuts)))) == whole
