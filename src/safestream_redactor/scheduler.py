"""RAM-aware parallel redaction across many files.

Redaction of a single file is already constant-memory and streaming; the
scheduler parallelises *across* files with a process pool, so a directory tree
is redacted using every core without the aggregate memory blowing up. Worker
count is clamped by both CPU and available RAM (read from ``/proc/meminfo``
when present) so peak memory stays bounded no matter how large the corpus is.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
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
    # entity-type name -> number of redactions in this file (never content)
    counts: dict[str, int] = field(default_factory=dict)
    chars_in: int = 0
    chars_out: int = 0
    decode_replacements: int = 0


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
    stats = _WORKER_REDACTOR.redact_file(in_path, out_path, encoding=_WORKER_ENCODING)
    return RedactResult(
        in_path,
        out_path,
        os.path.getsize(out_path),
        dict(stats.counts),
        stats.chars_in,
        stats.chars_out,
        stats.decode_replacements,
    )


def redact_tree(
    input_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    redactor: Redactor,
    *,
    workers: int | None = None,
    encoding: str = "utf-8",
    offline_guard: bool = True,
    progress: Callable[[int, int], None] | None = None,
) -> list[RedactResult]:
    """Redact every file under ``input_dir`` into ``output_dir`` in parallel.

    The output tree mirrors the input tree. Returns one :class:`RedactResult`
    per file, in sorted input-path order regardless of completion order. Uses a
    process pool sized by :func:`ram_aware_workers`; falls back to in-process
    execution when a single worker suffices. ``progress``, if given, is called
    ``(files_done, files_total)`` after each file completes.
    """
    in_root = Path(input_dir)
    out_root = Path(output_dir)
    # Walk without following symlinks: a symlinked directory could escape the
    # input tree (redacting/writing outside it) and a symlinked file could point
    # at a device (/dev/zero) — neither is intended when redacting a directory.
    # os.walk(followlinks=False) both skips descent into symlinked dirs and lets
    # us drop symlinked files, portably across Python versions.
    files: list[Path] = []
    for root, _dirs, names in os.walk(in_root, followlinks=False):
        root_path = Path(root)
        for name in names:
            p = root_path / name
            if p.is_file() and not p.is_symlink():
                files.append(p)
    files.sort()
    if not files:
        return []
    jobs = [(str(p), str(out_root / p.relative_to(in_root))) for p in files]
    total = len(jobs)

    n = ram_aware_workers(redactor, workers)
    if n == 1 or total == 1:
        _init_worker(redactor, encoding, offline_guard)
        results = []
        for done, job in enumerate(jobs, start=1):
            results.append(_redact_one(job))
            if progress:
                progress(done, total)
        return results

    with ProcessPoolExecutor(
        max_workers=n,
        initializer=_init_worker,
        initargs=(redactor, encoding, offline_guard),
    ) as pool:
        # submit keyed by index so results can be restored to input order even
        # though as_completed yields them as they finish (for live progress)
        futures = {pool.submit(_redact_one, job): i for i, job in enumerate(jobs)}
        by_index: dict[int, RedactResult] = {}
        for done, fut in enumerate(as_completed(futures), start=1):
            by_index[futures[fut]] = fut.result()
            if progress:
                progress(done, total)
        return [by_index[i] for i in range(total)]
