"""Opt-in **hard** offline modes — kernel-enforced egress containment.

The default :mod:`safestream_redactor.netguard` monkeypatches Python's socket
layer. That stops accidental egress by this process's Python code, but a native
extension issuing raw syscalls, a ``ctypes`` call into libc, or a subprocess can
bypass it. The two modes here close that gap with the kernel itself, at the cost
of being platform-specific and irreversible for the life of the process.

Both are **opt-in** (`--offline-hard MODE`), applied once before any work (and
before worker processes are forked, so children inherit them). Neither is a
substitute for a container-level policy where you control the runtime; they are
what an *unprivileged-ish* process can enforce on itself.

Exactly what each mode covers — and does not
--------------------------------------------

``netns`` — ``unshare(CLONE_NEWNET)``
    Moves the process into a fresh network namespace whose only interface is a
    **down** loopback. Result: no network at all — every protocol, every socket,
    including loopback, for this process *and every child it forks/execs*, native
    code included. It does **not** affect other processes on the host, and it
    needs ``CAP_SYS_ADMIN`` (root) or, unprivileged, a kernel that allows a new
    user namespace (tried as a fallback). Because loopback is down, this mode is
    for pure offline redaction, not for anything that talks to ``127.0.0.1``
    (e.g. ``serve``/``mcp-serve`` over TCP).

``seccomp`` — block ``AF_INET``/``AF_INET6`` socket creation
    Installs a seccomp-bpf filter that makes ``socket(2)`` for the IPv4/IPv6
    families fail with ``EACCES``, for this process and every child (the filter
    survives ``fork`` and ``execve`` under ``NO_NEW_PRIVS``), native code
    included. It does **not** touch already-open sockets, and it leaves
    ``AF_UNIX``/``AF_NETLINK`` alone (so multiprocessing pipes keep working).
    Note: classic seccomp-bpf cannot dereference the ``sockaddr`` pointer, so it
    cannot filter ``connect()``/``sendto()`` *by destination address*; blocking
    IP-socket *creation* outright is the enforceable primitive, and for offline
    use it is the stronger choice — no IP socket can be opened at all. Loopback
    IP sockets are blocked too, same caveat as ``netns``.

Both return a :class:`HardModeResult` and never raise: an unsupported platform or
a refused syscall degrades to ``applied=False`` with a reason, and the caller
keeps the best-effort monkeypatch guard.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
from dataclasses import dataclass

__all__ = ["HardModeResult", "enable_network_namespace", "enable_seccomp_inet_block"]

# clone/unshare flags
_CLONE_NEWNET = 0x40000000
_CLONE_NEWUSER = 0x10000000

# prctl / seccomp constants
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_SET_MODE_FILTER = 1

# BPF opcodes
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

# seccomp return actions
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EACCES = 13

# socket domains
_AF_INET = 2
_AF_INET6 = 10

# seccomp_data field offsets (struct seccomp_data): nr=0, arch=4, args[0]=16
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG0 = 16

# per-architecture: (AUDIT_ARCH, socket syscall nr, seccomp syscall nr)
_ARCH_TABLE: dict[str, tuple[int, int, int]] = {
    "x86_64": (0xC000003E, 41, 317),
    "aarch64": (0xC00000B7, 198, 277),
    "arm64": (0xC00000B7, 198, 277),
}


@dataclass(frozen=True, slots=True)
class HardModeResult:
    """Outcome of enabling a hard offline mode."""

    applied: bool
    mode: str  # "netns" | "seccomp" | "none"
    reason: str


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    )


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def enable_network_namespace() -> HardModeResult:
    """Enter a fresh, empty network namespace via ``unshare(CLONE_NEWNET)``.

    Tries privileged ``unshare(CLONE_NEWNET)`` first (works as root); on failure
    retries ``unshare(CLONE_NEWUSER|CLONE_NEWNET)`` for the unprivileged path.
    Process-wide and inherited by children; irreversible for this process.
    """
    if not hasattr(os, "fork") or os.name != "posix":  # pragma: no cover - non-POSIX
        return HardModeResult(False, "none", "network namespaces are Linux-only")
    try:
        libc = _libc()
    except OSError as exc:  # pragma: no cover - libc always present on Linux
        return HardModeResult(False, "none", f"libc unavailable: {exc}")
    # privileged path
    if libc.unshare(_CLONE_NEWNET) == 0:
        return HardModeResult(True, "netns", "entered a new network namespace (CLONE_NEWNET)")
    priv_errno = ctypes.get_errno()
    # unprivileged path: a new user namespace grants CAP_SYS_ADMIN within it
    ctypes.set_errno(0)
    if libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNET) == 0:
        return HardModeResult(
            True, "netns", "entered a new user+network namespace (unprivileged path)"
        )
    unpriv_errno = ctypes.get_errno()
    return HardModeResult(
        False,
        "none",
        f"unshare(CLONE_NEWNET) failed (errno {priv_errno}: {os.strerror(priv_errno)}); "
        f"unprivileged user+net namespace also failed (errno {unpriv_errno}: "
        f"{os.strerror(unpriv_errno)}). Needs CAP_SYS_ADMIN or unprivileged userns support",
    )


def _build_inet_block_filter(audit_arch: int, socket_nr: int) -> ctypes.Array[_SockFilter]:
    """BPF program: fail socket(AF_INET/AF_INET6, ...) with EACCES, else allow.

    See the module docstring for why creation is blocked rather than connect().
    Instruction layout (indices): 0 load arch, 1 arch-guard, 2 load nr,
    3 socket-guard, 4 load domain, 5/6 domain compares, 7 DENY, 8 ALLOW.
    """
    deny = _SECCOMP_RET_ERRNO | (_EACCES & 0xFFFF)
    prog = [
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_ARCH),
        # if arch mismatches what we built for, do not enforce (allow) — we only
        # know the syscall numbers for the audited arch
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 6, audit_arch),
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_NR),
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 4, socket_nr),
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _OFF_ARG0),
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, _AF_INET),  # ==INET -> DENY(7)
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 0, 1, _AF_INET6),  # ==INET6 -> DENY else ALLOW
        _SockFilter(_BPF_RET | _BPF_K, 0, 0, deny),
        _SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW),
    ]
    return (_SockFilter * len(prog))(*prog)


def enable_seccomp_inet_block() -> HardModeResult:
    """Install a seccomp-bpf filter blocking ``AF_INET``/``AF_INET6`` sockets.

    Process-wide and inherited across ``fork``/``execve`` (under
    ``NO_NEW_PRIVS``); irreversible for this process.
    """
    if os.name != "posix":  # pragma: no cover - non-POSIX
        return HardModeResult(False, "none", "seccomp is Linux-only")
    machine = platform.machine()
    entry = _ARCH_TABLE.get(machine)
    if entry is None:  # pragma: no cover - only common arches in CI
        return HardModeResult(
            False, "none", f"no audited seccomp syscall table for architecture {machine!r}"
        )
    audit_arch, socket_nr, seccomp_nr = entry
    try:
        libc = _libc()
    except OSError as exc:  # pragma: no cover
        return HardModeResult(False, "none", f"libc unavailable: {exc}")
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:  # pragma: no cover - rare
        err = ctypes.get_errno()
        return HardModeResult(
            False, "none", f"prctl(NO_NEW_PRIVS) failed (errno {err}: {os.strerror(err)})"
        )
    filt = _build_inet_block_filter(audit_arch, socket_nr)
    prog = _SockFprog(len(filt), ctypes.cast(filt, ctypes.POINTER(_SockFilter)))
    # Prefer the seccomp(2) syscall; fall back to prctl(PR_SET_SECCOMP).
    ctypes.set_errno(0)
    rc = libc.syscall(seccomp_nr, _SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(prog))
    if rc != 0:
        rc = libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    if rc != 0:  # pragma: no cover - kernel without seccomp filter support
        err = ctypes.get_errno()
        return HardModeResult(
            False, "none", f"installing seccomp filter failed (errno {err}: {os.strerror(err)})"
        )
    return HardModeResult(
        True, "seccomp", "seccomp-bpf filter installed: AF_INET/AF_INET6 socket creation blocked"
    )
