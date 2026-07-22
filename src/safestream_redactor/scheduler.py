"""RAM-aware parallel redaction across many files.

Redaction of a single file is already constant-memory and streaming; the
scheduler parallelises *across* files with a process pool, so a directory tree
is redacted using every core without the aggregate memory blowing up. Worker
count is clamped by both CPU and available RAM (read from ``/proc/meminfo``
when present) so peak memory stays bounded no matter how large the corpus is.
"""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from safestream_redactor.redactor import Redactor

# Rough per-worker resident budget: interpreter + compiled patterns + the
# streaming buffers (chunk + overlap). Deliberately generous so we err toward
# fewer workers rather than exhausting RAM.
_PER_WORKER_BASE = 96 * 1024 * 1024


@dataclass(slots=True)
class RedactResult:
    """Outcome of redacting one file."""

    input_path: str
    output_path: str
    bytes_written: int


def _available_memory() -> int | None:
    """Bytes of available RAM from /proc/meminfo, or None if unavailable."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def ram_aware_workers(redactor: Redactor, requested: int | None = None) -> int:
    """Choose a worker count from CPU count, available RAM, and the buffer size.

    An explicit ``requested`` value is honoured (only floored at 1); otherwise
    the count is the CPU count capped by ``available_ram / per_worker_budget``.
    """
    if requested is not None:
        return max(1, requested)
    cpu = os.cpu_count() or 1
    per_worker = _PER_WORKER_BASE + redactor.chunk_size + redactor.overlap
    available = _available_memory()
    mem_cap = cpu if available is None else max(1, available // per_worker)
    return max(1, min(cpu, mem_cap))


# --- worker-process globals ------------------------------------------------

_WORKER_REDACTOR: Redactor | None = None
_WORKER_ENCODING = "utf-8"


def _init_worker(redactor: Redactor, encoding: str, offline_guard: bool) -> None:
    global _WORKER_REDACTOR, _WORKER_ENCODING
    if offline_guard:
        from safestream_redactor import netguard

        netguard.install()
    _WORKER_REDACTOR = redactor
    _WORKER_ENCODING = encoding


def _redact_one(job: tuple[str, str]) -> RedactResult:
    assert _WORKER_REDACTOR is not None
    in_path, out_path = job
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    _WORKER_REDACTOR.redact_file(in_path, out_path, encoding=_WORKER_ENCODING)
    return RedactResult(in_path, out_path, os.path.getsize(out_path))


def redact_tree(
    input_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    redactor: Redactor,
    *,
    workers: int | None = None,
    encoding: str = "utf-8",
    offline_guard: bool = True,
) -> list[RedactResult]:
    """Redact every file under ``input_dir`` into ``output_dir`` in parallel.

    The output tree mirrors the input tree. Returns one :class:`RedactResult`
    per file. Uses a process pool sized by :func:`ram_aware_workers`; falls back
    to in-process execution when a single worker suffices.
    """
    in_root = Path(input_dir)
    out_root = Path(output_dir)
    files = sorted(p for p in in_root.rglob("*") if p.is_file())
    if not files:
        return []
    jobs = [(str(p), str(out_root / p.relative_to(in_root))) for p in files]

    n = ram_aware_workers(redactor, workers)
    if n == 1 or len(jobs) == 1:
        _init_worker(redactor, encoding, offline_guard)
        return [_redact_one(job) for job in jobs]

    with ProcessPoolExecutor(
        max_workers=n,
        initializer=_init_worker,
        initargs=(redactor, encoding, offline_guard),
    ) as pool:
        return list(pool.map(_redact_one, jobs))
