"""Checks for the review tools: Presidio wrapping and the Loghub label audit."""

from __future__ import annotations

from benchmarks.loghub_label_audit import _HOSTNAME, _is_ip
from benchmarks.wrap_presidio import _unbounded


def test_unbounded_lookahead_detection() -> None:
    # Presidio's low-confidence PAN pattern reads to the end of the text under DOTALL
    assert _unbounded(r"\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b")
    assert not _unbounded(r"\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b")
    assert not _unbounded(r"(?<=key=)[A-Za-z0-9]{20}")


def test_audit_value_shapes() -> None:
    assert _is_ip("103.207.39.16") and _is_ip("::1")
    assert not _is_ip("103.207.39.16 ")  # the trailing space the audit found
    assert _HOSTNAME.match("5.36.59.76.dynamic-dsl-ip.omantel.net.om")
    assert not _HOSTNAME.match("")
