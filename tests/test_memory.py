"""Constant-memory proof: redact a ~1 GB generated file and assert that
Python heap allocations stay flat.

These are excluded from the default run (see addopts in pyproject.toml).
Run them with:

    pytest -m memory -o addopts=''

Set SAFESTREAM_MEMTEST_MB to shrink the file for a quicker local check, e.g.
SAFESTREAM_MEMTEST_MB=100 pytest -m memory -o addopts=''
"""

import os
import tracemalloc

import pytest

from safestream_redactor import Redactor

SIZE_MB = int(os.environ.get("SAFESTREAM_MEMTEST_MB", "1024"))

LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com logged in "
    "from 10.20.30.40 ref 4111-1111-1111-1111 ssn: 123-45-6789 ok\n"
)


@pytest.fixture(scope="module")
def big_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("mem") / "big.log"
    block = LINE * 2048  # ~256 KB per write keeps generation fast
    block_size = len(block.encode())
    with open(path, "w", encoding="utf-8") as f:
        written = 0
        target = SIZE_MB * 1024 * 1024
        while written < target:
            f.write(block)
            written += block_size
    yield path
    path.unlink()


@pytest.mark.memory
def test_constant_memory_on_large_file(big_file, tmp_path):
    out = tmp_path / "out.log"
    redactor = Redactor(chunk_size=64 * 1024, overlap=4 * 1024)

    tracemalloc.start()
    redactor.redact_file(big_file, out)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Peak Python allocations must be a small multiple of the chunk size —
    # nowhere near the input size. 16 MB is orders of magnitude below 1 GB.
    assert peak < 16 * 1024 * 1024, f"peak allocations {peak / 1e6:.1f} MB — not constant memory"

    # sanity: output really was redacted
    with open(out, encoding="utf-8") as f:
        head = f.read(4096)
    assert "[REDACTED]" in head
    assert "bob.smith@corp.example.com" not in head
    out.unlink()
