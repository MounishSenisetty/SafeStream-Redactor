"""SafeStream memory subsystem: a streaming, crash-safe, OS-adjacent memory core
with a novel episodic-synthesis layer.

This package is intentionally self-contained and stdlib-only. See
``docs/MEMSTREAM.md`` for the architecture and the extension API.
"""

from __future__ import annotations

from safestream_redactor.memstream.events import (
    CHECKPOINT,
    DATA,
    Codec,
    JsonBodyCodec,
    MemoryEvent,
    RecordType,
)

__all__ = [
    "CHECKPOINT",
    "DATA",
    "Codec",
    "JsonBodyCodec",
    "MemoryEvent",
    "RecordType",
]
