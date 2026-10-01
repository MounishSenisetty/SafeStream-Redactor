"""Linux file-system DLP: watch directories and audit, redact, or block secrets.

``safestream fanotify --watch DIR --mode MODE`` runs a daemon over one or more
directory trees:

``audit``
    After a file is written and closed, scan it and log what it contains
    (entity types and counts only, never the matched text).
``redact``
    After a file is written and closed, rewrite it in place with every detection
    redacted (atomically: a temp file renamed over the original).
``block``
    Deny ``read()`` of any file that contains a detection. Every read of a
    watched file waits for the daemon's verdict (cached per inode, size and
    mtime, so a file is scanned once per change); the reader gets ``EPERM``.

What ``fanotify`` can and cannot do decides the design. Its permission events
(``FAN_ACCESS_PERM``, ``FAN_OPEN_PERM``) let a daemon allow or deny an access,
but there is no event that exposes a ``write()``'s data before it reaches the
file — the pre-content events of Linux 6.14+ report the byte *range* being
accessed, not the writer's buffer. So writes cannot be scanned and blocked in
flight; ``block`` stops secrets from being *read back out* of the watched
tree, and ``redact`` removes them right after the writer closes the file.
Intercepting the write itself needs an LSM/eBPF hook or a FUSE layer.

Privileges: ``fanotify`` needs ``CAP_SYS_ADMIN``. Without it, ``audit`` and
``redact`` fall back to ``inotify`` (``IN_CLOSE_WRITE``), which any user can use
on files they can read; ``block`` refuses to start, because nothing else can
enforce it — the daemon never pretends to protect what it cannot.

Limits worth knowing: reads through ``mmap`` do not generate ``FAN_ACCESS_PERM``;
directories created after start are picked up by a periodic rescan (every
``rescan`` seconds); and in ``redact`` mode a reader can see the secret in the
window between the writer's close and the rewrite.
"""

from __future__ import annotations

import codecs
import ctypes
import ctypes.util
import errno
import json
import os
import select
import struct
import sys
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import IO, Any

from safestream_redactor._atomic import atomic_output
from safestream_redactor.engine import read_chunks
from safestream_redactor.redactor import Redactor

MODES = ("audit", "redact", "block")

# <linux/fanotify.h>
FAN_ACCESS_PERM = 0x0002_0000
FAN_CLOSE_WRITE = 0x0000_0008
FAN_EVENT_ON_CHILD = 0x0800_0000
FAN_Q_OVERFLOW = 0x0000_4000
FAN_CLASS_NOTIF = 0x00
FAN_CLASS_CONTENT = 0x04
FAN_CLOEXEC = 0x01
FAN_NONBLOCK = 0x02
FAN_MARK_ADD = 0x01
FAN_ALLOW = 0x01
FAN_DENY = 0x02
FAN_NOFD = -1
FANOTIFY_METADATA_VERSION = 3
_FAN_META = struct.Struct("=IBBHQii")  # event_len, vers, reserved, metadata_len, mask, fd, pid
_FAN_RESPONSE = struct.Struct("=iI")  # fd, response

# <linux/inotify.h>
IN_CLOSE_WRITE = 0x0000_0008
IN_MOVED_TO = 0x0000_0080
IN_CREATE = 0x0000_0100
IN_Q_OVERFLOW = 0x0000_4000
IN_ISDIR = 0x4000_0000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000
_IN_EVENT = struct.Struct("=iIII")  # wd, mask, cookie, len

DEFAULT_MAX_SCAN_BYTES = 64 * 1024 * 1024


class WatchUnavailable(RuntimeError):
    """The requested watch mode cannot be enforced on this system or with these privileges."""


# --- scanning ---------------------------------------------------------------


def _fd_chunks(fd: int, chunk_size: int, max_bytes: int) -> Iterator[str]:
    """Decode a file descriptor's content (from offset 0) into text chunks."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    offset = 0
    while offset < max_bytes:
        data = os.pread(fd, min(chunk_size, max_bytes - offset), offset)
        if not data:
            break
        offset += len(data)
        if text := decoder.decode(data):
            yield text
    if tail := decoder.decode(b"", final=True):
        yield tail


def scan_fd(
    redactor: Redactor, fd: int, *, max_bytes: int, stop_at_first: bool = False
) -> Counter[str] | None:
    """Detection counts by entity type for the file open at ``fd``.

    ``None`` when the file is larger than ``max_bytes`` (not scanned). With
    ``stop_at_first`` the scan ends at the first detection, which is all a
    block/allow verdict needs.
    """
    if os.fstat(fd).st_size > max_bytes:
        return None
    counts: Counter[str] = Counter()
    for _segment, detections in redactor.detect_stream(
        _fd_chunks(fd, redactor.chunk_size, max_bytes)
    ):
        for det in detections:
            counts[det.entity_type.value] += 1
        if counts and stop_at_first:
            break
    return counts


def redact_in_place(redactor: Redactor, path: str) -> int:
    """Redact ``path`` atomically (temp file renamed over it); returns detections."""
    from safestream_redactor.report import RedactionStats

    stats = RedactionStats()
    with atomic_output(path) as out:
        for piece in redactor.redact_stream(read_chunks(path, redactor.chunk_size), stats):
            out.write(piece)
    return sum(stats.counts.values())


# --- verdict cache ----------------------------------------------------------


@dataclass
class _VerdictCache:
    """``(dev, ino) -> ((size, mtime_ns, ctime_ns), counts)``, least-recently-used.

    ``counts`` are the file's detections by type (empty: clean). An entry only
    applies while the file's size and timestamps are unchanged.
    """

    limit: int = 4096
    _items: OrderedDict[tuple[int, int], tuple[tuple[int, int, int], Counter[str]]] = field(
        default_factory=OrderedDict
    )

    def get(self, st: os.stat_result) -> Counter[str] | None:
        hit = self._items.get((st.st_dev, st.st_ino))
        if hit is None or hit[0] != (st.st_size, st.st_mtime_ns, st.st_ctime_ns):
            return None
        self._items.move_to_end((st.st_dev, st.st_ino))
        return hit[1]

    def put(self, st: os.stat_result, counts: Counter[str]) -> None:
        self._items[(st.st_dev, st.st_ino)] = ((st.st_size, st.st_mtime_ns, st.st_ctime_ns), counts)
        self._items.move_to_end((st.st_dev, st.st_ino))
        while len(self._items) > self.limit:
            self._items.popitem(last=False)


# --- kernel interfaces (ctypes; no third-party dependency) -------------------


def _libc() -> Any:
    lib = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    lib.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    lib.fanotify_mark.argtypes = [
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_int,
        ctypes.c_char_p,
    ]
    lib.inotify_init1.argtypes = [ctypes.c_int]
    lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    return lib


def _os_error(call: str) -> OSError:
    err = ctypes.get_errno()
    return OSError(err, f"{call}: {os.strerror(err)}")


def _walk_dirs(roots: list[str]) -> Iterator[str]:
    for root in roots:
        yield root
        for dirpath, dirnames, _files in os.walk(root):
            for d in dirnames:
                yield os.path.join(dirpath, d)


def _under(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


@dataclass
class WatchEvent:
    """A file under a watched root was written (``written``) or is being read."""

    path: str
    fd: int = -1  # fanotify only: an O_RDONLY fd on the file, owned by the source
    pid: int = 0
    permission: bool = False  # a read waiting on our verdict (block mode)


class _FanotifySource:
    """fanotify group with inode marks on every watched directory."""

    def __init__(self, roots: list[str], block: bool) -> None:  # pragma: no cover - root
        self._lib = _libc()
        cls = FAN_CLASS_CONTENT if block else FAN_CLASS_NOTIF
        fd = self._lib.fanotify_init(
            cls | FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY | os.O_LARGEFILE | os.O_CLOEXEC
        )
        if fd < 0:
            raise _os_error("fanotify_init")
        self.fd = fd
        self._roots = roots
        self._mask = FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD | (FAN_ACCESS_PERM if block else 0)
        self._marked: set[str] = set()
        self.rescan()

    def rescan(self) -> None:  # pragma: no cover - root
        for d in _walk_dirs(self._roots):
            if d in self._marked:
                continue
            if self._lib.fanotify_mark(self.fd, FAN_MARK_ADD, self._mask, -1, os.fsencode(d)) < 0:
                err = ctypes.get_errno()
                if err not in (errno.ENOENT, errno.ENOTDIR):
                    raise _os_error(f"fanotify_mark({d})")
                continue
            self._marked.add(d)

    def events(self) -> Iterator[WatchEvent]:  # pragma: no cover - root
        try:
            buf = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return
        pos = 0
        while pos + _FAN_META.size <= len(buf):
            event_len, vers, _r, _ml, mask, fd, pid = _FAN_META.unpack_from(buf, pos)
            pos += event_len
            if vers != FANOTIFY_METADATA_VERSION or fd == FAN_NOFD:
                continue  # queue overflow (FAN_Q_OVERFLOW) or a format we don't read
            try:
                path = os.readlink(f"/proc/self/fd/{fd}")
                yield WatchEvent(path, fd, pid, permission=bool(mask & FAN_ACCESS_PERM))
            finally:
                os.close(fd)

    def respond(self, event: WatchEvent, allow: bool) -> None:  # pragma: no cover - root
        os.write(self.fd, _FAN_RESPONSE.pack(event.fd, FAN_ALLOW if allow else FAN_DENY))

    def close(self) -> None:  # pragma: no cover - root
        # pending permission events are answered "allow" by the kernel on close
        os.close(self.fd)


class _InotifySource:
    """Unprivileged fallback: IN_CLOSE_WRITE (+ moved-in files) on every directory."""

    def __init__(self, roots: list[str]) -> None:
        self._lib = _libc()
        fd = self._lib.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:  # pragma: no cover - exhausted inotify instances
            raise _os_error("inotify_init1")
        self.fd = fd
        self._roots = roots
        self._dirs: dict[int, str] = {}
        self.rescan()

    def rescan(self) -> None:
        known = set(self._dirs.values())
        for d in _walk_dirs(self._roots):
            if d in known:
                continue
            mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
            wd = self._lib.inotify_add_watch(self.fd, os.fsencode(d), mask)
            if wd >= 0:
                self._dirs[wd] = d

    def events(self) -> Iterator[WatchEvent]:
        try:
            buf = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return
        pos = 0
        new_dirs = False
        while pos + _IN_EVENT.size <= len(buf):
            wd, mask, _cookie, length = _IN_EVENT.unpack_from(buf, pos)
            name = buf[pos + _IN_EVENT.size : pos + _IN_EVENT.size + length].rstrip(b"\0")
            pos += _IN_EVENT.size + length
            directory = self._dirs.get(wd)
            if directory is None or not name:
                continue
            path = os.path.join(directory, os.fsdecode(name))
            if mask & IN_ISDIR:
                new_dirs = new_dirs or bool(mask & (IN_CREATE | IN_MOVED_TO))
            elif mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                yield WatchEvent(path)
        if new_dirs:
            self.rescan()

    def respond(self, event: WatchEvent, allow: bool) -> None:  # pragma: no cover
        raise WatchUnavailable("inotify cannot answer permission events")

    def close(self) -> None:
        os.close(self.fd)


# --- the daemon --------------------------------------------------------------


@dataclass
class DlpWatcher:
    """Watch ``roots`` and audit, redact, or block files that contain detections."""

    redactor: Redactor
    roots: list[str]
    mode: str = "audit"
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES
    fail_open: bool = False
    force_inotify: bool = False
    rescan_interval: float = 2.0
    log: IO[str] = field(default_factory=lambda: sys.stdout)
    backend_name: str = ""
    _cache: _VerdictCache = field(default_factory=_VerdictCache)
    # (dev, ino, mtime_ns, pid) already reported as blocked: FAN_ACCESS_PERM
    # fires on every read(), so log each denial once per file version and reader
    _reported: OrderedDict[tuple[int, int, int, int], None] = field(default_factory=OrderedDict)
    _own: dict[str, tuple[int, int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {self.mode!r}")
        if not sys.platform.startswith("linux"):
            raise WatchUnavailable("file-system watching is Linux-only (fanotify / inotify)")
        self.roots = [os.path.realpath(r) for r in self.roots]
        for r in self.roots:
            if not os.path.isdir(r):
                raise ValueError(f"not a directory: {r}")

    def _emit(self, record: dict[str, Any]) -> None:
        # metadata only: path, types, counts, action — never matched text
        self.log.write(json.dumps({"ts": round(time.time(), 3), **record}) + "\n")
        self.log.flush()

    def _open_source(self) -> _FanotifySource | _InotifySource:
        if not self.force_inotify:
            try:
                source = _FanotifySource(self.roots, block=self.mode == "block")
            except OSError as exc:
                if self.mode == "block":
                    raise WatchUnavailable(
                        f"block mode needs fanotify permission events, which need "
                        f"CAP_SYS_ADMIN ({exc.strerror}); refusing to run without enforcement"
                    ) from exc
                self._emit({"event": "fallback", "to": "inotify", "reason": exc.strerror})
            else:  # pragma: no cover - root
                self.backend_name = "fanotify"
                return source
        if self.mode == "block":
            raise WatchUnavailable("block mode cannot run on inotify (no permission events)")
        self.backend_name = "inotify"
        return _InotifySource(self.roots)

    def _scan(self, event: WatchEvent, stop_at_first: bool) -> Counter[str] | None:
        if event.fd >= 0:  # pragma: no cover - fanotify
            return scan_fd(
                self.redactor, event.fd, max_bytes=self.max_scan_bytes, stop_at_first=stop_at_first
            )
        fd = os.open(event.path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            return scan_fd(
                self.redactor, fd, max_bytes=self.max_scan_bytes, stop_at_first=stop_at_first
            )
        finally:
            os.close(fd)

    def _verdict(self, event: WatchEvent) -> bool:  # pragma: no cover - fanotify block
        """True to allow the pending read."""
        st = os.fstat(event.fd)
        counts = self._cache.get(st)
        if counts is None:
            try:
                counts = self._scan(event, stop_at_first=True)
            except (OSError, ValueError) as exc:
                self._emit({"event": "error", "path": event.path, "error": str(exc)})
                return self.fail_open
            if counts is None:
                self._emit({"event": "oversize", "path": event.path, "allowed": self.fail_open})
                return self.fail_open
            self._cache.put(st, counts)
        if not counts:
            return True
        key = (st.st_dev, st.st_ino, st.st_mtime_ns, event.pid)
        if key not in self._reported:
            self._reported[key] = None
            if len(self._reported) > 4096:
                self._reported.popitem(last=False)
            self._emit(
                {"event": "blocked", "path": event.path, "pid": event.pid, "types": dict(counts)}
            )
        return False

    def _on_written(self, event: WatchEvent) -> None:
        if event.pid == os.getpid():
            return  # pragma: no cover - our own rewrite (fanotify reports pids)
        try:
            st = os.stat(event.path)
        except FileNotFoundError:
            return  # a temp file already renamed away (ours or another writer's)
        if self._own.get(event.path) == (st.st_ino, st.st_mtime_ns):
            return  # the file we just rewrote: already clean
        try:
            counts = self._scan(event, stop_at_first=False)
        except (OSError, ValueError) as exc:
            self._emit({"event": "error", "path": event.path, "error": str(exc)})
            return
        if counts is None:
            self._emit({"event": "oversize", "path": event.path})
            return
        if self.mode == "block" and event.fd >= 0:  # pragma: no cover - fanotify block
            # warm the verdict cache: the first read need not scan again
            self._cache.put(os.fstat(event.fd), counts)
        if not counts:
            return
        record: dict[str, Any] = {"event": "finding", "path": event.path, "types": dict(counts)}
        if self.mode == "redact":
            redact_in_place(self.redactor, event.path)
            st = os.stat(event.path)
            self._own[event.path] = (st.st_ino, st.st_mtime_ns)
            record["action"] = "redacted"
        else:
            record["action"] = "logged"
        self._emit(record)

    def run(
        self,
        stop: threading.Event | None = None,
        ready: Callable[[str], None] | None = None,
    ) -> None:
        """Watch until ``stop`` is set (or SIGINT/SIGTERM via the CLI)."""
        stop = stop or threading.Event()
        source = self._open_source()
        try:
            self._emit(
                {
                    "event": "watching",
                    "backend": self.backend_name,
                    "mode": self.mode,
                    "roots": self.roots,
                }
            )
            if ready is not None:
                ready(self.backend_name)
            poller = select.poll()
            poller.register(source.fd, select.POLLIN)
            next_rescan = time.monotonic() + self.rescan_interval
            while not stop.is_set():
                for _fd, _ev in poller.poll(200):
                    for event in source.events():
                        if not _under(event.path, self.roots):
                            if event.permission:  # pragma: no cover - fanotify block
                                source.respond(event, True)
                            continue
                        if event.permission:  # pragma: no cover - fanotify block
                            allow = event.pid == os.getpid() or self._verdict(event)
                            source.respond(event, allow)
                        else:
                            self._on_written(event)
                if time.monotonic() >= next_rescan:
                    source.rescan()
                    next_rescan = time.monotonic() + self.rescan_interval
        finally:
            source.close()
