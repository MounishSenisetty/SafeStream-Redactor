"""Hard offline modes: seccomp AF_INET block and network-namespace isolation.

Two kinds of coverage:

* **In-process, with a fake libc** — exercises every branch of the enable
  functions without issuing a real, irreversible syscall in the pytest process.
* **Real enforcement, in a forked child** — proves the kernel actually blocks
  what the mode claims. These skip on kernels/CI that don't permit the operation.
"""

from __future__ import annotations

import os
import socket
import sys
from collections.abc import Callable

import pytest

import safestream_redactor.netguard_hard as nh

pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork") or sys.platform == "win32", reason="hard offline modes are POSIX-only"
)


# --- fake libc so the Python branches run without real syscalls --------------


class _FakeLibc:
    def __init__(self, unshare=(0,), no_new_privs=0, syscall=0, set_seccomp=0):
        self._unshare = list(unshare)
        self.no_new_privs_ret = no_new_privs
        self.syscall_ret = syscall
        self.set_seccomp_ret = set_seccomp

    def unshare(self, _flags):
        return self._unshare.pop(0) if self._unshare else 0

    def prctl(self, option, *_a):
        if option == nh._PR_SET_NO_NEW_PRIVS:
            return self.no_new_privs_ret
        if option == nh._PR_SET_SECCOMP:
            return self.set_seccomp_ret
        return 0

    def syscall(self, *_a):
        return self.syscall_ret


def _use_fake(monkeypatch, **kw):
    monkeypatch.setattr(nh, "_libc", lambda: _FakeLibc(**kw))


def test_netns_privileged_path(monkeypatch):
    _use_fake(monkeypatch, unshare=(0,))
    r = nh.enable_network_namespace()
    assert r.applied and r.mode == "netns" and "CLONE_NEWNET" in r.reason


def test_netns_unprivileged_fallback(monkeypatch):
    _use_fake(monkeypatch, unshare=(-1, 0))  # priv fails, user+net succeeds
    r = nh.enable_network_namespace()
    assert r.applied and "unprivileged" in r.reason


def test_netns_both_paths_fail(monkeypatch):
    _use_fake(monkeypatch, unshare=(-1, -1))
    r = nh.enable_network_namespace()
    assert not r.applied and r.mode == "none"


def test_seccomp_syscall_path(monkeypatch):
    _use_fake(monkeypatch, no_new_privs=0, syscall=0)
    r = nh.enable_seccomp_inet_block()
    assert r.applied and r.mode == "seccomp"


def test_seccomp_prctl_fallback_path(monkeypatch):
    # seccomp(2) syscall fails, prctl(PR_SET_SECCOMP) succeeds
    _use_fake(monkeypatch, no_new_privs=0, syscall=-1, set_seccomp=0)
    r = nh.enable_seccomp_inet_block()
    assert r.applied


def test_seccomp_no_new_privs_failure(monkeypatch):
    _use_fake(monkeypatch, no_new_privs=-1)
    r = nh.enable_seccomp_inet_block()
    assert not r.applied and "NO_NEW_PRIVS" in r.reason


def test_seccomp_unknown_arch(monkeypatch):
    monkeypatch.setattr(nh.platform, "machine", lambda: "sparc64")
    r = nh.enable_seccomp_inet_block()
    assert not r.applied and "architecture" in r.reason


def test_build_filter_shape():
    filt = nh._build_inet_block_filter(0xC000003E, 41)
    assert len(filt) == 9
    # last instruction allows, second-to-last denies with EACCES
    assert filt[8].k == nh._SECCOMP_RET_ALLOW
    assert filt[7].k == (nh._SECCOMP_RET_ERRNO | nh._EACCES)


# --- real enforcement in a forked child --------------------------------------


def _in_child(fn: Callable[[], int | None]) -> int:
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process
        code = 0
        try:
            code = fn() or 0
        except BaseException:
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + (status & 0x7F)


def _seccomp_supported() -> bool:
    return _in_child(lambda: 0 if nh.enable_seccomp_inet_block().applied else 60) == 0


def _netns_supported() -> bool:
    return _in_child(lambda: 0 if nh.enable_network_namespace().applied else 60) == 0


def test_seccomp_really_blocks_inet_and_allows_unix():
    if not _seccomp_supported():
        pytest.skip("seccomp filtering not permitted in this environment")

    def fn() -> int:
        nh.enable_seccomp_inet_block()
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            return 10  # should not be reachable
        except PermissionError:
            pass
        # AF_UNIX must still work (multiprocessing depends on it)
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
        return 0

    assert _in_child(fn) == 0


def test_netns_really_blocks_outbound():
    if not _netns_supported():
        pytest.skip("network namespaces not permitted in this environment")

    def fn() -> int:
        nh.enable_network_namespace()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(("8.8.8.8", 53))
            return 10  # unreachable: no route in an empty netns
        except OSError:
            return 0

    assert _in_child(fn) == 0


def test_cli_offline_hard_seccomp_still_redacts(tmp_path):
    if not _seccomp_supported():
        pytest.skip("seccomp filtering not permitted in this environment")
    src = tmp_path / "in.txt"
    src.write_text("email a@b.io ssn 123-45-6789\n" * 40)
    out = tmp_path / "out.txt"

    def fn() -> int:
        from safestream_redactor.cli import main

        return main(["redact", str(src), "-o", str(out), "--offline-hard", "seccomp"])

    assert _in_child(fn) == 0
    text = out.read_text()
    assert "[REDACTED]" in text and "a@b.io" not in text


# --- CLI dispatch branches (in-process, no real syscalls) --------------------


def _fake(applied: bool, mode: str):
    return lambda: nh.HardModeResult(applied, mode if applied else "none", "stub")


def test_apply_offline_hard_none_is_noop(capsys):
    from safestream_redactor import cli

    cli._apply_offline_hard(None)
    assert capsys.readouterr().err == ""


def test_apply_offline_hard_reports_success(monkeypatch, capsys):
    from safestream_redactor import cli

    monkeypatch.setattr(nh, "enable_seccomp_inet_block", _fake(True, "seccomp"))
    cli._apply_offline_hard("seccomp")
    assert "offline hard mode active [seccomp]" in capsys.readouterr().err


def test_apply_offline_hard_auto_falls_back_to_seccomp(monkeypatch, capsys):
    from safestream_redactor import cli

    monkeypatch.setattr(nh, "enable_network_namespace", _fake(False, "netns"))
    monkeypatch.setattr(nh, "enable_seccomp_inet_block", _fake(True, "seccomp"))
    cli._apply_offline_hard("auto")
    assert "offline hard mode active [seccomp]" in capsys.readouterr().err


def test_apply_offline_hard_warns_on_total_failure(monkeypatch, capsys):
    from safestream_redactor import cli

    monkeypatch.setattr(nh, "enable_network_namespace", _fake(False, "netns"))
    monkeypatch.setattr(nh, "enable_seccomp_inet_block", _fake(False, "seccomp"))
    cli._apply_offline_hard("auto")
    assert "could not enable hard offline mode" in capsys.readouterr().err
