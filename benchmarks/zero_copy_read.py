"""Zero-copy I/O evaluation for the file-to-file redaction path.

Question: would ``mmap`` + ``madvise(MADV_SEQUENTIAL)``, ``preadv``, or
``splice``/``sendfile`` measurably speed up redaction while preserving constant
memory and byte-identical output?

This script measures, on the same generated file:

1. **decode-only** throughput of the current reader (``engine.read_chunks``,
   text mode with universal newlines) — the I/O + decode layer alone;
2. **mmap + madvise(SEQUENTIAL)** decode-only throughput — the zero-copy input;
3. **preadv** decode-only throughput — vectored positional reads;
4. **full redaction** throughput (``Redactor.redact_file``) — I/O + decode +
   detection + policy.

If (4) is far below (1)-(3), detection dominates and faster input I/O cannot
move end-to-end throughput — the honest reason zero-copy input is *not* adopted.
``splice``/``sendfile`` are inapplicable here by construction: redaction rewrites
the bytes, so output never equals input and a kernel-to-kernel copy cannot be
used. Run:

    python benchmarks/zero_copy_read.py --size-mb 128
"""

from __future__ import annotations

import argparse
import codecs
import contextlib
import io
import mmap
import os
import tempfile
import time
from collections.abc import Callable

from safestream_redactor import Redactor
from safestream_redactor.engine import read_chunks

LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com logged in "
    "from 10.20.30.40 ref 4111-1111-1111-1111 ssn: 123-45-6789 ok\n"
)
CHUNK = 64 * 1024


def _generate(path: str, size_mb: int) -> None:
    block = LINE * 2048
    block_bytes = len(block.encode())
    target = size_mb * 1024 * 1024
    with open(path, "w", encoding="utf-8") as f:
        written = 0
        while written < target:
            f.write(block)
            written += block_bytes


def _decode_only_read_chunks(path: str) -> int:
    total = 0
    for chunk in read_chunks(path, CHUNK):
        total += len(chunk)
    return total


def _decode_only_mmap(path: str) -> int:
    total = 0
    decoder = io.IncrementalNewlineDecoder(codecs.getincrementaldecoder("utf-8")(), translate=True)
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        with contextlib.suppress(OSError):
            mm.madvise(mmap.MADV_SEQUENTIAL)
        for off in range(0, len(mm), CHUNK):
            total += len(decoder.decode(mm[off : off + CHUNK]))
        total += len(decoder.decode(b"", True))
    return total


def _decode_only_preadv(path: str) -> int:
    total = 0
    decoder = io.IncrementalNewlineDecoder(codecs.getincrementaldecoder("utf-8")(), translate=True)
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        off = 0
        while off < size:
            bufs = [bytearray(CHUNK)]
            n = os.preadv(fd, bufs, off)
            if n <= 0:
                break
            total += len(decoder.decode(bytes(bufs[0][:n])))
            off += n
        total += len(decoder.decode(b"", True))
    finally:
        os.close(fd)
    return total


def _full_redaction(path: str) -> int:
    out = path + ".redacted"
    try:
        stats = Redactor(load_plugins=False).redact_file(path, out)
        return stats.chars_in
    finally:
        with contextlib.suppress(OSError):
            os.unlink(out)


def _time(label: str, fn: Callable[[str], int], path: str, size_bytes: int) -> float:
    # one warm-up so the page cache is hot for every variant equally
    fn(path)
    best = min(_run(fn, path) for _ in range(3))
    mbps = (size_bytes / 1e6) / best
    print(f"{label:<28} {best * 1e3:8.1f} ms   {mbps:8.1f} MB/s")
    return mbps


def _run(fn: Callable[[str], int], path: str) -> float:
    t0 = time.perf_counter()
    fn(path)
    return time.perf_counter() - t0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size-mb", type=int, default=128)
    ap.add_argument("--path", default=None, help="use an existing file instead of generating one")
    args = ap.parse_args()

    tmp = None
    if args.path:
        path = args.path
    else:
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        tmp = path
        print(f"generating {args.size_mb} MB test file ...")
        _generate(path, args.size_mb)

    size = os.path.getsize(path)
    print(f"file: {size / 1e6:.1f} MB   chunk: {CHUNK // 1024} KB   (best of 3, page cache hot)\n")
    print(f"{'variant':<28} {'time':>11}   {'throughput':>11}")
    print("-" * 54)
    try:
        base = _time("read_chunks (current)", _decode_only_read_chunks, path, size)
        mm = _time("mmap + madvise(SEQ)", _decode_only_mmap, path, size)
        pv = _time("preadv", _decode_only_preadv, path, size)
        full = _time("full redaction", _full_redaction, path, size)
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)

    print("\nsummary")
    print("-" * 54)
    print(f"input I/O is ~{base / full:.0f}-{max(mm, pv) / full:.0f}x faster than full redaction,")
    print("so detection dominates end-to-end time; faster input cannot move it.")
    print("mmap/preadv vs read_chunks:", f"{mm / base:.2f}x / {pv / base:.2f}x (decode-only)")


if __name__ == "__main__":
    main()
