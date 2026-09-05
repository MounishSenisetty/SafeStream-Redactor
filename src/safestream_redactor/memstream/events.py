"""The event model and its serialization codec.

A :class:`MemoryEvent` is the atomic unit the memory subsystem stores, indexes,
and synthesizes. It carries a little structured metadata (used by the novel
layer to build episodes and entity timelines) plus an opaque ``body`` of raw
bytes so callers can attach an arbitrary payload without the core needing to
understand it.

``seq`` and ``ts_ns`` are assigned by the log store when the event is durably
appended, so a freshly built event carries the sentinel ``-1`` for both. This
keeps identity monotonic and owned by exactly one component (the writer),
which is what gives the whole system its total ordering.

The wire form is deliberately simple and dependency-free: a length-prefixed
JSON header for the structured fields followed by the raw body bytes. JSON
cannot hold arbitrary bytes, so the body is kept *outside* the JSON rather
than base64-encoded into it — that keeps binary payloads exact and avoids a
33% size tax on the hot path.
"""

from __future__ import annotations

import enum
import json
import struct
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class RecordType(enum.IntEnum):
    """The kind of record a WAL frame carries.

    ``DATA`` frames hold an encoded :class:`MemoryEvent`. ``CHECKPOINT`` frames
    hold a reducer/synthesis progress marker so recovery can resume without
    replaying the entire log. New record types can be added here without
    breaking older logs: an unknown type is skipped by readers that don't
    understand it (see :mod:`safestream_redactor.memstream.wal`).
    """

    DATA = 1
    CHECKPOINT = 2


# Convenience module-level aliases (mirrors how the detectors expose constants).
DATA = RecordType.DATA
CHECKPOINT = RecordType.CHECKPOINT


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    """One immutable memory event.

    Attributes
    ----------
    kind:
        A short category label (e.g. ``"detection"``, ``"log"``). Used by
        reducers to decide what to do with an event.
    session:
        The stream/session this event belongs to. The episodic synthesizer
        groups events into episodes per session.
    key:
        An optional secondary key (e.g. an entity type or a document id).
    entities:
        Tags fed into the inverted entity index for timeline queries.
    attrs:
        Small structured string metadata. Kept as ``str``→``str`` so the wire
        form is a plain JSON object with no ambiguity on decode.
    body:
        Opaque payload bytes. Never interpreted by the core.
    seq:
        Monotonic sequence number, assigned by the store on append. ``-1``
        until then.
    ts_ns:
        Wall-clock nanosecond timestamp, assigned by the store on append.
        ``-1`` until then.
    """

    kind: str
    session: str = ""
    key: str = ""
    entities: tuple[str, ...] = ()
    attrs: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    seq: int = -1
    ts_ns: int = -1


@runtime_checkable
class Codec(Protocol):
    """Serializes a :class:`MemoryEvent` to and from the WAL payload bytes.

    The payload excludes ``seq``/``ts_ns``/record-type — those live in the WAL
    frame header and are supplied back to :meth:`decode`. This lets the store
    own identity and timestamps while the codec owns only the caller's data.
    An alternate codec (e.g. a more compact binary or an encrypted one) is a
    documented extension point.
    """

    def encode(self, event: MemoryEvent) -> bytes:
        """Serialize the caller-owned fields of ``event`` to bytes."""
        ...

    def decode(self, payload: bytes, seq: int, ts_ns: int) -> MemoryEvent:
        """Reconstruct an event from ``payload`` plus store-assigned identity."""
        ...


_HEADER_LEN = struct.Struct("<I")  # u32 little-endian length prefix


class JsonBodyCodec:
    """Default codec: ``[u32 header_len][header_json][body_bytes]``.

    The header JSON holds the structured fields; the body follows verbatim so
    arbitrary bytes round-trip exactly.
    """

    def encode(self, event: MemoryEvent) -> bytes:
        header = {
            "kind": event.kind,
            "session": event.session,
            "key": event.key,
            "entities": list(event.entities),
            "attrs": event.attrs,
        }
        header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return _HEADER_LEN.pack(len(header_bytes)) + header_bytes + event.body

    def decode(self, payload: bytes, seq: int, ts_ns: int) -> MemoryEvent:
        if len(payload) < _HEADER_LEN.size:
            raise ValueError("payload too short for header length prefix")
        (header_len,) = _HEADER_LEN.unpack_from(payload, 0)
        start = _HEADER_LEN.size
        end = start + header_len
        if end > len(payload):
            raise ValueError("payload truncated: header extends past end")
        try:
            header = json.loads(payload[start:end].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
            raise ValueError(f"corrupt event header: {exc}") from exc
        return MemoryEvent(
            kind=str(header["kind"]),
            session=str(header.get("session", "")),
            key=str(header.get("key", "")),
            entities=tuple(header.get("entities", ())),
            attrs=dict(header.get("attrs", {})),
            body=payload[end:],
            seq=seq,
            ts_ns=ts_ns,
        )
