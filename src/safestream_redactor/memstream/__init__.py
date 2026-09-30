"""SafeStream memory subsystem (UNFINISHED, NOT DISTRIBUTED).

The event model and codec of a planned streaming, crash-safe event log. Its
write-ahead log is not written yet and nothing in the redaction path imports
this package, so it is excluded from the published wheel and sdist (see
``[tool.hatch.build]`` in ``pyproject.toml``). It exists only in a source
checkout; do not depend on it.
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
