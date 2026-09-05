"""Write-ahead log: append/replay, durability across reopen, checkpoints,
growth past the initial capacity, and — most importantly — crash recovery
that truncates a torn tail rather than trusting it."""

import struct

import pytest

from safestream_redactor.memstream.events import CHECKPOINT, DATA

# The WAL module is written in a later step; until then this spec collects and
# skips cleanly instead of erroring, so it can live in the tree without turning
# the suite red. The guard becomes a no-op once ``wal.py`` exists.
MmapWAL = pytest.importorskip("safestream_redactor.memstream.wal").MmapWAL


def test_append_and_read_roundtrip(tmp_path):
    with MmapWAL(tmp_path / "log") as wal:
        s0 = wal.append(b"one")
        s1 = wal.append(b"two")
        s2 = wal.append(b"three")
        assert (s0, s1, s2) == (0, 1, 2)
        recs = list(wal.read_from(0))
        assert [r.seq for r in recs] == [0, 1, 2]
        assert [r.payload for r in recs] == [b"one", b"two", b"three"]
        assert all(r.rtype == DATA for r in recs)
        assert all(r.ts_ns > 0 for r in recs)


def test_read_from_seq_filters(tmp_path):
    with MmapWAL(tmp_path / "log") as wal:
        for i in range(5):
            wal.append(f"e{i}".encode())
        assert [r.seq for r in wal.read_from(3)] == [3, 4]
        assert [r.seq for r in wal.read_from(99)] == []


def test_empty_payload_roundtrips(tmp_path):
    with MmapWAL(tmp_path / "log") as wal:
        wal.append(b"")
        (rec,) = list(wal.read_from(0))
        assert rec.payload == b""


def test_persistence_across_reopen(tmp_path):
    p = tmp_path / "log"
    with MmapWAL(p) as wal:
        wal.append(b"alpha")
        wal.append(b"beta")
    with MmapWAL(p) as wal:  # recovery path
        assert wal.last_seq == 1
        assert [r.payload for r in wal.read_from(0)] == [b"alpha", b"beta"]
        # appends continue the sequence, they do not restart it
        assert wal.append(b"gamma") == 2


def test_checkpoints(tmp_path):
    p = tmp_path / "log"
    with MmapWAL(p) as wal:
        wal.append(b"a")
        wal.append(b"b")
        wal.checkpoint(b"progress=1")
        wal.append(b"c")
        cp = wal.last_checkpoint()
        assert cp is not None
        assert cp.rtype == CHECKPOINT
        assert cp.payload == b"progress=1"
        # data reads skip checkpoint records
        assert [r.payload for r in wal.read_from(0)] == [b"a", b"b", b"c"]


def test_growth_past_initial_capacity(tmp_path):
    # Force many small growths by starting with a tiny capacity.
    with MmapWAL(tmp_path / "log", initial_capacity=64) as wal:
        payloads = [f"record-number-{i:04d}".encode() for i in range(200)]
        for pl in payloads:
            wal.append(pl)
        assert [r.payload for r in wal.read_from(0)] == payloads
        assert wal.last_seq == 199


def test_recovery_truncates_torn_tail(tmp_path):
    """A half-written last record (torn write) must be dropped on recovery,
    and the log must remain appendable with the correct next sequence."""
    p = tmp_path / "log"
    with MmapWAL(p) as wal:
        wal.append(b"durable-1")
        wal.append(b"durable-2")
        good_size = wal.data_end
        wal.append(b"this-one-will-be-torn")
    # Simulate a crash mid-append: chop the file back into the middle of the
    # third record (but keep the first two intact).
    with open(p, "r+b") as f:
        f.truncate(good_size + 5)  # 5 stray bytes of a torn frame
    with MmapWAL(p) as wal:
        assert [r.payload for r in wal.read_from(0)] == [b"durable-1", b"durable-2"]
        assert wal.last_seq == 1
        assert wal.append(b"recovered") == 2
    with MmapWAL(p) as wal:
        assert [r.payload for r in wal.read_from(0)] == [
            b"durable-1",
            b"durable-2",
            b"recovered",
        ]


def test_recovery_drops_crc_corrupted_record(tmp_path):
    p = tmp_path / "log"
    with MmapWAL(p) as wal:
        wal.append(b"keep-me")
        start_of_second = wal.data_end
        wal.append(b"corrupt-me")
    # Flip a byte inside the second record's payload -> CRC mismatch.
    with open(p, "r+b") as f:
        data = bytearray(f.read())
        data[-1] ^= 0xFF
        f.seek(0)
        f.write(data)
    with MmapWAL(p) as wal:
        assert [r.payload for r in wal.read_from(0)] == [b"keep-me"]
        assert wal.last_seq == 0
        assert wal.data_end == start_of_second  # write cursor rewound to the good prefix


def test_rejects_foreign_file(tmp_path):
    p = tmp_path / "notawal"
    p.write_bytes(b"this is definitely not a safestream wal header" + struct.pack("<I", 0))
    with pytest.raises(ValueError):
        MmapWAL(p)


def test_fsync_always_mode_is_durable(tmp_path):
    p = tmp_path / "log"
    with MmapWAL(p, fsync="always") as wal:
        wal.append(b"x")
        wal.append(b"y")
    with MmapWAL(p) as wal:
        assert [r.payload for r in wal.read_from(0)] == [b"x", b"y"]


def test_stats(tmp_path):
    with MmapWAL(tmp_path / "log") as wal:
        wal.append(b"a")
        wal.append(b"bb")
        st = wal.stats()
        assert st["records"] == 2
        assert st["last_seq"] == 1
        assert st["data_bytes"] > 0
