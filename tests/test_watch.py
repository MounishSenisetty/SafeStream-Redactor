"""File-system DLP daemon (``safestream fanotify``): inotify paths run anywhere on
Linux; the fanotify paths need CAP_SYS_ADMIN and run only as root (CI runs them
with sudo; they are skipped otherwise)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="fanotify/inotify are Linux-only"
)

SECRET = "deploy key AKIAIOSFODNN7EXAMPLE and ssn 123-45-6789\n"
CLEAN = "just an ordinary line\n"


def _fanotify_available() -> bool:
    if os.geteuid() != 0:
        return False
    import ctypes

    lib = ctypes.CDLL(None, use_errno=True)
    fd = lib.fanotify_init(0x04 | 0x01, os.O_RDONLY)  # FAN_CLASS_CONTENT | FAN_CLOEXEC
    if fd < 0:
        return False
    os.close(fd)
    return True


needs_fanotify = pytest.mark.skipif(
    not _fanotify_available(), reason="needs root with CAP_SYS_ADMIN (fanotify)"
)


def _wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class _Daemon:
    """A DlpWatcher on a background thread, logging into a buffer."""

    def __init__(self, root: Path, mode: str, **kw) -> None:
        from safestream_redactor import Redactor
        from safestream_redactor.watch import DlpWatcher

        self.log = io.StringIO()
        self.watcher = DlpWatcher(Redactor(), [str(root)], mode=mode, log=self.log, **kw)
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self.watcher.run, args=(self.stop, lambda _b: self.ready.set()), daemon=True
        )

    def __enter__(self) -> _Daemon:
        self.thread.start()
        assert self.ready.wait(10)
        return self

    def __exit__(self, *exc) -> None:
        self.stop.set()
        self.thread.join(10)

    def records(self) -> list[dict]:
        return [json.loads(line) for line in self.log.getvalue().splitlines()]


def test_inotify_audit_logs_metadata_never_content(tmp_path):
    with _Daemon(tmp_path, "audit", force_inotify=True, rescan_interval=0.1) as d:
        assert d.watcher.backend_name == "inotify"
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.txt").write_text(SECRET)
        (tmp_path / "clean.txt").write_text(CLEAN)
        assert _wait_for(lambda: any(r["event"] == "finding" for r in d.records()))
        # a directory created after start is watched after the next rescan
        time.sleep(0.4)
        (tmp_path / "sub" / "b.txt").write_text(SECRET)
        assert _wait_for(lambda: sum(r["event"] == "finding" for r in d.records()) == 2), (
            d.records()
        )
    findings = [r for r in d.records() if r["event"] == "finding"]
    assert {Path(r["path"]).name for r in findings} == {"a.txt", "b.txt"}
    assert findings[0]["types"] == {"aws_key": 1, "ssn": 1}
    assert all(r["action"] == "logged" for r in findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in d.log.getvalue()
    assert (tmp_path / "a.txt").read_text() == SECRET  # audit never modifies


def test_inotify_redact_rewrites_in_place_once(tmp_path):
    with _Daemon(tmp_path, "redact", force_inotify=True) as d:
        target = tmp_path / "app.log"
        target.write_text(SECRET + CLEAN)
        assert _wait_for(lambda: "[REDACTED]" in target.read_text())
        time.sleep(0.5)  # the rename of our own rewrite must not trigger a second pass
    assert target.read_text() == "deploy key [REDACTED] and ssn [REDACTED]\n" + CLEAN
    assert [r["action"] for r in d.records() if r["event"] == "finding"] == ["redacted"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["app.log"]  # no temp left


def test_fanotify_denied_falls_back_to_inotify_but_block_refuses(tmp_path, monkeypatch):
    from safestream_redactor import Redactor, watch

    def denied(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(watch, "_FanotifySource", denied)
    with _Daemon(tmp_path, "audit") as d:
        assert d.watcher.backend_name == "inotify"
    assert d.records()[0] == {**d.records()[0], "event": "fallback", "to": "inotify"}

    blocker = watch.DlpWatcher(Redactor(), [str(tmp_path)], mode="block", log=io.StringIO())
    with pytest.raises(watch.WatchUnavailable, match="CAP_SYS_ADMIN"):
        blocker.run(threading.Event())
    forced = watch.DlpWatcher(
        Redactor(), [str(tmp_path)], mode="block", force_inotify=True, log=io.StringIO()
    )
    with pytest.raises(watch.WatchUnavailable, match="permission events"):
        forced.run(threading.Event())


def test_cli_refuses_unenforceable_block_and_bad_dirs(tmp_path, capsys):
    from safestream_redactor.cli import main

    assert main(["fanotify", "--watch", str(tmp_path), "--mode", "block", "--inotify"]) == 2
    assert "permission events" in capsys.readouterr().err
    assert main(["fanotify", "--watch", str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_scan_fd_counts_and_size_limit(tmp_path):
    from safestream_redactor import Redactor
    from safestream_redactor.watch import scan_fd

    path = tmp_path / "f.txt"
    path.write_text(CLEAN * 100 + SECRET * 3)
    fd = os.open(path, os.O_RDONLY)
    try:
        assert scan_fd(Redactor(), fd, max_bytes=1 << 20) == {"aws_key": 3, "ssn": 3}
        assert sum(scan_fd(Redactor(), fd, max_bytes=1 << 20, stop_at_first=True).values()) >= 1
        assert scan_fd(Redactor(), fd, max_bytes=100) is None  # oversize: not scanned
    finally:
        os.close(fd)


def test_verdict_cache_invalidates_on_change_and_evicts(tmp_path):
    from collections import Counter

    from safestream_redactor.watch import _VerdictCache

    cache = _VerdictCache(limit=2)
    a, b, c = (tmp_path / n for n in "abc")
    for p in (a, b, c):
        p.write_text("x")
    cache.put(os.stat(a), Counter(ssn=1))
    assert cache.get(os.stat(a)) == {"ssn": 1}
    a.write_text("changed content")  # size/mtime change: stale entry ignored
    assert cache.get(os.stat(a)) is None
    cache.put(os.stat(b), Counter())
    cache.put(os.stat(c), Counter())
    cache.put(os.stat(a), Counter())  # third entry evicts the least recently used (b)
    assert cache.get(os.stat(b)) is None and cache.get(os.stat(c)) == {}


def test_watcher_rejects_bad_mode(tmp_path):
    from safestream_redactor import Redactor
    from safestream_redactor.watch import DlpWatcher

    with pytest.raises(ValueError, match="mode"):
        DlpWatcher(Redactor(), [str(tmp_path)], mode="quarantine")


# --- real fanotify (root) -----------------------------------------------------


def _start_cli(root: Path, mode: str, log: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "safestream_redactor",
            "fanotify",
            "--watch",
            str(root),
            "--mode",
            mode,
        ],
        stdout=log.open("w"),
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stderr.readline()
    assert "watching" in line and "fanotify" in line, line
    return proc


@needs_fanotify
def test_fanotify_block_denies_reads_of_secret_files(tmp_path):
    root = tmp_path / "watched"
    (root / "nested").mkdir(parents=True)
    log = tmp_path / "log.jsonl"
    proc = _start_cli(root, "block", log)
    try:
        secret, clean, nested = root / "s.txt", root / "c.txt", root / "nested" / "n.txt"
        secret.write_text(SECRET)
        clean.write_text(CLEAN)
        nested.write_text(SECRET)
        with pytest.raises(PermissionError):
            secret.read_text()
        with pytest.raises(PermissionError):
            nested.read_text()
        assert clean.read_text() == CLEAN
        # the verdict follows the content: clean the file and it reads again
        secret.write_text(CLEAN)
        assert _wait_for(lambda: _readable(secret))
        assert secret.read_text() == CLEAN
    finally:
        proc.terminate()
        proc.wait(10)
    records = [json.loads(x) for x in log.read_text().splitlines()]
    assert any(r["event"] == "blocked" for r in records)
    assert "AKIAIOSFODNN7EXAMPLE" not in log.read_text()


def _readable(path: Path) -> bool:
    try:
        path.read_text()
    except PermissionError:
        return False
    return True


@needs_fanotify
def test_fanotify_redact_rewrites_after_close(tmp_path):
    root = tmp_path / "watched"
    root.mkdir()
    proc = _start_cli(root, "redact", tmp_path / "log.jsonl")
    try:
        target = root / "out.log"
        target.write_text(SECRET)
        assert _wait_for(lambda: "[REDACTED]" in target.read_text())
    finally:
        proc.terminate()
        proc.wait(10)
    assert target.read_text() == "deploy key [REDACTED] and ssn [REDACTED]\n"
