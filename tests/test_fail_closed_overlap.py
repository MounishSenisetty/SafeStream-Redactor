"""Fail-closed overlap enforcement (R-ENG-2 / R-ENG-4).

An overlap smaller than the longest span a detector can emit lets a boundary-
straddling entity leak, so the engine must refuse -- before running when the
shortfall is knowable from declared requirements, and mid-stream when a
detector emits a span longer than it declared -- unless explicitly overridden.
"""

from __future__ import annotations

import logging

import pytest

from safestream_redactor import Redactor, WindowConfigurationError
from safestream_redactor.cli import main
from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.engine import stream_windows
from safestream_redactor.entities import Detection, EntityType


class _Plugin:
    """A third-party tier that declares ``declared`` but emits ``emitted``-long spans."""

    name = "plugin"

    def __init__(self, declared: int | None, emitted: int) -> None:
        if declared is not None:
            self.requirements = StreamingRequirements(max_span=declared)
        self.emitted = emitted

    def detect(self, text: str) -> list[Detection]:
        if len(text) < self.emitted:
            return []
        return [Detection(0, self.emitted, text[: self.emitted], EntityType.CUSTOM, 1.0)]


def _chunks(text: str, n: int):
    return (text[i : i + n] for i in range(0, len(text), n))


# --- before execution: declared requirements vs. overlap -----------------


def test_error_is_a_value_error_for_backward_compatibility() -> None:
    assert issubclass(WindowConfigurationError, ValueError)


def test_builtin_tiers_reject_a_too_small_overlap() -> None:
    with pytest.raises(WindowConfigurationError, match="safe minimum"):
        Redactor(overlap=16)


def test_plugin_declaring_more_than_overlap_fails_before_any_input() -> None:
    plugin = _Plugin(declared=64, emitted=8)
    with pytest.raises(WindowConfigurationError):
        Redactor(use_entropy=False, extra_detectors=[plugin], overlap=32)


def test_plugin_declaring_nothing_gets_the_conservative_default() -> None:
    plugin = _Plugin(declared=None, emitted=8)  # assumed 8 KiB
    with pytest.raises(WindowConfigurationError):
        Redactor(use_entropy=False, extra_detectors=[plugin], overlap=1024)


# --- during execution: span longer than overlap --------------------------


def test_overlong_span_halts_the_stream_by_default() -> None:
    plugin = _Plugin(declared=8, emitted=100)  # lies about its span
    with pytest.raises(WindowConfigurationError, match="longer than the overlap"):
        list(stream_windows(_chunks("z" * 500, 32), plugin.detect, overlap=64))


def test_overlong_span_in_a_redactor_halts_redact_stream() -> None:
    plugin = _Plugin(declared=8, emitted=100)  # passes the static check, then lies
    r = Redactor(use_entropy=False, extra_detectors=[plugin], types=["email"], overlap=8192)
    r.overlap = 64  # a window the plugin's real output does not fit in
    with pytest.raises(WindowConfigurationError):
        "".join(r.redact_stream(_chunks("z" * 500, 32)))


def test_overlong_span_does_not_halt_when_explicitly_allowed(caplog) -> None:
    plugin = _Plugin(declared=8, emitted=100)
    with caplog.at_level(logging.WARNING, logger="safestream_redactor.engine"):
        out = list(
            stream_windows(_chunks("z" * 500, 32), plugin.detect, overlap=64, strict_spans=False)
        )
    assert "".join(seg for seg, _ in out) == "z" * 500
    assert any("longer than the overlap" in r.message for r in caplog.records)


def test_span_within_overlap_is_untouched() -> None:
    plugin = _Plugin(declared=8, emitted=8)
    out = list(stream_windows(_chunks("z" * 500, 32), plugin.detect, overlap=64))
    assert "".join(seg for seg, _ in out) == "z" * 500


# --- the explicit override ------------------------------------------------


def test_override_flag_downgrades_construction_to_a_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        r = Redactor(overlap=16, allow_unsafe_overlap=True)
    assert r.allow_unsafe_overlap is True
    assert any("allow_unsafe_overlap" in rec.message for rec in caplog.records)


def test_cli_rejects_small_overlap_then_accepts_the_insecure_flag(tmp_path, capsys) -> None:
    src = tmp_path / "in.txt"
    src.write_text("mail bob@corp.example now\n")
    out = tmp_path / "out.txt"
    assert main(["redact", str(src), "-o", str(out), "--overlap", "16"]) != 0
    assert not out.exists()  # fail closed: no partial output
    rc = main(
        [
            "redact",
            str(src),
            "-o",
            str(out),
            "--overlap",
            "16",
            "--insecure-allow-leak-prone-overlap",
        ]
    )
    assert rc == 0
    assert "bob@corp.example" not in out.read_text()
