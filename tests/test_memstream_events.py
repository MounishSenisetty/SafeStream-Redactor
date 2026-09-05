"""Event model and codec: round-trip, framing, and stability of the wire form."""

from dataclasses import FrozenInstanceError

import pytest

from safestream_redactor.memstream.events import (
    DATA,
    JsonBodyCodec,
    MemoryEvent,
    RecordType,
)


def test_event_defaults():
    e = MemoryEvent(kind="log")
    assert e.seq == -1  # unassigned until appended
    assert e.ts_ns == -1
    assert e.session == ""
    assert e.key == ""
    assert e.entities == ()
    assert e.attrs == {}
    assert e.body == b""


def test_codec_roundtrip_full():
    codec = JsonBodyCodec()
    e = MemoryEvent(
        kind="detection",
        session="run-42",
        key="AWS_KEY",
        entities=("aws", "AKIA…"),
        attrs={"severity": "high", "count": "3"},
        body=b"\x00\x01binary\xffpayload",
    )
    payload = codec.encode(e)
    assert isinstance(payload, bytes)
    back = codec.decode(payload, seq=7, ts_ns=123)
    assert back.seq == 7
    assert back.ts_ns == 123
    assert back.kind == e.kind
    assert back.session == e.session
    assert back.key == e.key
    assert back.entities == e.entities
    assert back.attrs == e.attrs
    assert back.body == e.body  # arbitrary bytes survive intact


def test_codec_roundtrip_minimal():
    codec = JsonBodyCodec()
    e = MemoryEvent(kind="x")
    back = codec.decode(codec.encode(e), seq=0, ts_ns=0)
    assert back.kind == "x"
    assert back.body == b""
    assert back.entities == ()


def test_codec_rejects_truncated_payload():
    codec = JsonBodyCodec()
    payload = codec.encode(MemoryEvent(kind="log", body=b"hello"))
    with pytest.raises(ValueError):
        codec.decode(payload[:2], seq=1, ts_ns=1)


def test_record_types():
    assert RecordType.DATA == DATA
    assert RecordType.DATA != RecordType.CHECKPOINT


def test_event_is_hashable_frozen():
    e = MemoryEvent(kind="log")
    with pytest.raises(FrozenInstanceError):
        e.kind = "changed"  # type: ignore[misc]
