"""Low-level kernel hardening for the streaming engine.

These pin invariants of ``engine.stream_windows`` that the higher-level
``Redactor`` tests do not reach directly:

* the emit-boundary retreat stays correct even when a detector returns
  *overlapping* detections (the pipeline normally resolves overlaps first, but
  ``stream_windows`` is a public surface a custom detector can drive) — a span
  must never be cut, and no detection may be silently dropped (R-ENG-1);
* an over-long span (longer than the overlap) is surfaced with a warning rather
  than swallowed (R-ENG-4);
* memory stays bounded when a detection is anchored at the very start of the
  buffer and keeps straddling the boundary (R-ENG-3).
"""

from __future__ import annotations

import logging

import pytest

from safestream_redactor.engine import (
    WindowConfigurationError,
    _check_overlong,
    _retreat_boundary,
    stream_windows,
)
from safestream_redactor.entities import Detection, EntityType


def _det(start: int, end: int) -> Detection:
    return Detection(start, end, "x" * (end - start), EntityType.CUSTOM, 1.0)


def chunked(text: str, size: int):
    for i in range(0, len(text), size):
        yield text[i : i + size]


# --- _retreat_boundary ------------------------------------------------------


def test_retreat_single_straddler():
    # non-overlapping case: one detection straddles, boundary retreats to it
    assert _retreat_boundary([_det(90, 105)], 100) == 90


def test_retreat_no_straddler_is_noop():
    assert _retreat_boundary([_det(10, 20), _det(30, 40)], 25) == 25


def test_retreat_overlapping_chain_reaches_fixpoint():
    # A straddles 100 -> retreat to 90; B=[80,95] then straddles 90 -> 80;
    # C=[70,82] then straddles 80 -> 70. A single left-to-right pass would stop
    # at 90 and leave B/C cut; the fixpoint pulls the boundary clear of all.
    dets = [_det(70, 82), _det(80, 95), _det(90, 105)]
    assert _retreat_boundary(dets, 100) == 70


def test_retreat_terminates_on_zero_anchored_span():
    # a detection anchored at 0 pulls the boundary to 0 (caller then carries)
    assert _retreat_boundary([_det(0, 50)], 30) == 0


# --- overlapping detections must not lose a span through stream_windows ------


class _OverlappingKeyDetector:
    """Emits an overlapping detection for every ``KEY`` occurrence.

    Two ``KEY`` markers closer together than ``span`` yield overlapping
    detections — exactly the input the pipeline's ``resolve_overlaps`` normally
    prevents, used here to prove the engine stays correct without it.
    """

    name = "overlapping-key"

    def __init__(self, span: int = 8) -> None:
        self.span = span

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        idx = text.find("KEY")
        while idx != -1:
            end = min(idx + self.span, len(text))
            found.append(Detection(idx, end, text[idx:end], EntityType.CUSTOM, 1.0))
            idx = text.find("KEY", idx + 1)
        return found


def _absolute_detections(text: str, chunk_size: int, overlap: int):
    detector = _OverlappingKeyDetector(span=8)
    out: list[tuple[int, int, str]] = []
    base = 0
    for segment, dets in stream_windows(chunked(text, chunk_size), detector.detect, overlap):
        for d in dets:
            # every yielded detection must be wholly inside its segment (never cut)
            assert segment[d.start : d.end] == d.text
            out.append((base + d.start, base + d.end, d.text))
        base += len(segment)
    assert base == len(text)  # segments reassemble to the whole input
    return sorted(out)


def test_overlapping_detections_are_never_cut_or_dropped():
    # two KEY markers 5 apart with span 8 -> detections [p,p+8] and [p+5,p+13]
    # overlap; place the whole cluster so chunk boundaries fall inside it.
    text = "....KEY..KEY........ and KEY here KEYKEY end"
    whole = _absolute_detections(text, chunk_size=len(text), overlap=16)
    assert whole, "fixture should contain detections"
    for chunk_size in range(1, 20):
        streamed = _absolute_detections(text, chunk_size, overlap=16)
        assert streamed == whole, f"lost/cut a detection at chunk_size={chunk_size}"


# --- over-long span warning (R-ENG-4) ---------------------------------------


class _FixedSpanDetector:
    name = "fixed-span"

    def __init__(self, span: int) -> None:
        self.span = span

    def detect(self, text: str) -> list[Detection]:
        if len(text) < self.span:
            return []
        return [Detection(0, self.span, text[: self.span], EntityType.CUSTOM, 1.0)]


def test_check_overlong_fails_closed_or_flags_once():
    with pytest.raises(WindowConfigurationError):
        _check_overlong([_det(0, 40)], overlap=16, already=False)
    # strict=False: fires once, then reports "already warned" so callers don't repeat it
    assert _check_overlong([_det(0, 40)], overlap=16, already=False, strict=False) is True
    assert _check_overlong([_det(0, 40)], overlap=16, already=True) is True
    assert _check_overlong([_det(0, 10)], overlap=16, already=False) is False
    assert _check_overlong([], overlap=16, already=False) is False


def test_overlong_span_raises_by_default_and_warns_when_allowed(caplog):
    text = "z" * 200
    detector = _FixedSpanDetector(span=40)  # longer than the overlap below
    # one chunk carrying the whole text: the span is seen in the first
    # window (empty prefix), so it survives to the over-long check
    with pytest.raises(WindowConfigurationError, match="longer than the overlap"):
        list(stream_windows([text], detector.detect, overlap=16))
    with caplog.at_level(logging.WARNING, logger="safestream_redactor.engine"):
        list(stream_windows([text], detector.detect, overlap=16, strict_spans=False))
    assert any("longer than the overlap" in r.message for r in caplog.records)


def test_span_within_overlap_does_not_warn(caplog):
    text = "z" * 200
    detector = _FixedSpanDetector(span=10)
    with caplog.at_level(logging.WARNING, logger="safestream_redactor.engine"):
        list(stream_windows(chunked(text, 16), detector.detect, overlap=64))
    assert not any("longer than the overlap" in r.message for r in caplog.records)
