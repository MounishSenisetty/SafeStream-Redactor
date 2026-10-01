"""Kernel-level memory enforcement for ``--memory-limit`` (RLIMIT_AS).

The real-enforcement tests run inside a ``fork``ed child, never the pytest
process: installing a low RLIMIT_AS in-process would make later allocations in
the whole test run fail. The child sets the cap, provokes (or stays under) it,
and its exit code carries the verdict back.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

import pytest

import safestream_redactor.memory_budget as mb
from safestream_redactor.memory_budget import AddressSpaceLimit, enforce_address_space_limit

# The module needs fork (POSIX) for the real-enforcement tests; Windows has no
# resource module at all, so skip the whole module there.
pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork") or sys.platform == "win32",
    reason="RLIMIT_AS enforcement is POSIX-only",
)

# RLIMIT_AS is only *reliably enforced* on Linux. macOS accepts setrlimit(RLIMIT_AS)
# but does not honour it (allocations past the cap still succeed), so a test that
# actually provokes the kernel must be Linux-only; the graceful-fallback behaviour
# on other platforms is covered by the mocked tests below.
linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="RLIMIT_AS is only reliably enforced on Linux",
)

MB = 1024 * 1024


def _in_child(fn: Callable[[], int | None]) -> int:
    """Run ``fn`` in a forked child; return its exit code (42 == MemoryError)."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process, not measured by coverage
        code = 0
        try:
            code = fn() or 0
        except MemoryError:
            code = 42
        except BaseException:
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + (status & 0x7F)


@linux_only
def test_enforce_applies_and_allows_allocation_within_budget():
    def fn() -> int:
        info = enforce_address_space_limit(256 * MB)
        assert info.applied and info.mechanism == "rlimit_as"
        assert info.cap_bytes is not None
        buf = bytearray(16 * MB)  # comfortably inside the 256 MB headroom
        buf[-1] = 1
        return 0

    assert _in_child(fn) == 0


@linux_only
def test_enforce_fails_closed_on_over_allocation():
    def fn() -> int:
        info = enforce_address_space_limit(24 * MB)
        assert info.applied
        # far exceed the 24 MB headroom -> the kernel refuses -> MemoryError
        hoard = []
        for _ in range(128):
            hoard.append(bytearray(8 * MB))  # must stay referenced so pages commit
        assert hoard  # unreached: MemoryError fires first
        return 0

    assert _in_child(fn) == 42  # MemoryError, i.e. the process failed closed


def test_enforce_only_tightens_an_existing_lower_limit(monkeypatch):
    # hermetic: mock resource so no real RLIMIT_AS is set and no fork is needed;
    # this pins the clamping arithmetic (never raise a pre-existing lower cap).
    import resource

    preset_hard = 150 * MB
    recorded: dict[str, tuple[int, int]] = {}
    monkeypatch.setattr(mb, "_current_address_space_bytes", lambda: 100 * MB)
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (preset_hard, preset_hard))
    monkeypatch.setattr(
        resource, "setrlimit", lambda _which, limits: recorded.__setitem__("l", limits)
    )
    info = enforce_address_space_limit(4096 * MB)  # would compute ~4.2 GB
    assert info.applied
    soft, hard = recorded["l"]
    assert hard == preset_hard  # the lower pre-existing hard cap is preserved
    assert soft <= hard


def test_enforce_falls_back_when_address_space_unreadable(monkeypatch):
    # force the "can't read current VSZ" branch: no setrlimit is attempted, so
    # this is safe to run in-process
    monkeypatch.setattr(mb, "_current_address_space_bytes", lambda: None)
    info = enforce_address_space_limit(64 * MB)
    assert not info.applied
    assert info.mechanism == "none"
    assert "address space" in info.reason


def test_enforce_never_raises_on_setrlimit_refusal(monkeypatch):
    import resource

    def boom(*_a, **_k):
        raise OSError("nope")

    monkeypatch.setattr(resource, "setrlimit", boom)
    info = enforce_address_space_limit(64 * MB)
    assert not info.applied and info.mechanism == "none"


# --- CLI wiring: branch coverage without touching the test process's rlimit ---


def _fake_enforced(applied: bool):
    def _enforce(growth: int) -> AddressSpaceLimit:
        return AddressSpaceLimit(applied, "rlimit_as" if applied else "none", 1, "test")

    return _enforce


def test_cli_reports_kernel_enforcement(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(mb, "enforce_address_space_limit", _fake_enforced(True))
    from safestream_redactor.cli import main

    src = tmp_path / "in.txt"
    src.write_text("email a@b.io\n" * 50)
    out = tmp_path / "out.txt"
    # --no-ner: a spaCy model cannot load under a 128 MB address-space cap
    args = ["redact", str(src), "-o", str(out), "--memory-limit", "128MB", "--allow-network"]
    rc = main([*args, "--no-ner"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "enforced by kernel (RLIMIT_AS)" in err
    assert "[REDACTED]" in out.read_text()


def test_cli_warns_when_enforcement_unavailable(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(mb, "enforce_address_space_limit", _fake_enforced(False))
    from safestream_redactor.cli import main

    src = tmp_path / "in.txt"
    src.write_text("email a@b.io\n" * 50)
    out = tmp_path / "out.txt"
    # --no-ner: a spaCy model cannot load under a 128 MB address-space cap
    args = ["redact", str(src), "-o", str(out), "--memory-limit", "128MB", "--allow-network"]
    rc = main([*args, "--no-ner"])
    assert rc == 0
    assert "kernel memory enforcement unavailable" in capsys.readouterr().err


def test_cli_maps_memory_error_to_exit_3(monkeypatch, capsys):
    from safestream_redactor import cli

    def boom(_args):
        raise MemoryError

    monkeypatch.setattr(cli, "_cmd_redact", boom)
    rc = cli.main(["redact", "in.txt", "-o", "out.txt", "--allow-network"])
    assert rc == 3
    assert "resource-exhaustion" in capsys.readouterr().err
