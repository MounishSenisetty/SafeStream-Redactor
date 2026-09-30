"""Atomic file replacement shared by every writer of user-visible output.

A redactor must never leave a partially written file that looks complete: a
downstream consumer would ship the unredacted remainder, or trust a truncated
report. Every output (redacted files, stdin-to-file runs, the parallel
assembler, JSON run reports) is therefore written to a temporary file in the
destination directory and moved into place with :func:`os.replace`, which is
atomic on POSIX and Windows when source and target share a filesystem.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterator
from typing import IO


def _match_destination_mode(tmp_path: str, out_path: str) -> None:
    """Give the temp file the permissions the destination would have had.

    ``mkstemp`` creates 0o600 files; a plain ``open(out, "w")`` would instead
    keep an existing file's mode, or apply the process umask to a new one.
    Matching that keeps atomic replacement behaviourally identical to the
    direct write it replaced.
    """
    try:
        mode = stat.S_IMODE(os.stat(out_path).st_mode)
    except OSError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    with contextlib.suppress(OSError):
        os.chmod(tmp_path, mode)


@contextlib.contextmanager
def _replace_on_success(path: str) -> Iterator[int]:
    """Yield a temp-file descriptor beside ``path``; move it over ``path`` on success.

    On any exception — including ``KeyboardInterrupt`` — the temp file is
    removed and ``path`` is left untouched.
    """
    fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(path) or ".",
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
    )
    try:
        yield fd
        _match_destination_mode(tmp_path, path)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


@contextlib.contextmanager
def atomic_output(path: str | os.PathLike[str], *, encoding: str = "utf-8") -> Iterator[IO[str]]:
    """Text file that replaces ``path`` only if the block completes.

    ``newline=""`` writes line endings exactly as given: a redactor must not
    rewrite ``\r\n`` (or turn ``\n`` into ``os.linesep``).
    """
    with (
        _replace_on_success(os.fspath(path)) as fd,
        open(fd, "w", encoding=encoding, newline="") as f,
    ):
        yield f


@contextlib.contextmanager
def atomic_output_bytes(path: str | os.PathLike[str]) -> Iterator[IO[bytes]]:
    """Binary counterpart of :func:`atomic_output`."""
    with _replace_on_success(os.fspath(path)) as fd, open(fd, "wb") as f:
        yield f
