"""Detector interface. Implement this Protocol to plug a new tier in."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from safestream_redactor.entities import Detection


@runtime_checkable
class Detector(Protocol):
    """Anything with a name and a ``detect`` method is a detector."""

    name: str

    def detect(self, text: str) -> list[Detection]: ...
