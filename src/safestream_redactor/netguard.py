"""Runtime network-egress guard — best-effort, defense-in-depth.

Once installed, this monkeypatches the socket layer so any attempt to open a
connection to a non-loopback address raises :class:`NetworkAccessError` before
a byte is sent. That reliably stops *accidental* egress by this process, its
detector plugins, and its pure-Python dependencies.

It is **not** a security boundary and must not be relied on as one: a native
extension issuing raw syscalls, a spawned subprocess (``curl`` ...), a
``ctypes`` call into libc, or any other process on the host can all bypass it,
and it does nothing about disk-based exfiltration. For a hard guarantee, run
with networking disabled at the OS/container level (``--network none``, a
network namespace, or a seccomp egress policy) in addition to this guard. See
``SECURITY.md`` for the threat model.

The guard is *not* installed on import — importing the library never changes
global socket behaviour. The CLI installs it by default (opt out with
``--allow-network``); library users call :func:`install` explicitly.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class NetworkAccessError(RuntimeError):
    """Raised when guarded code attempts a non-loopback network connection."""


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "::"})
_original_connect: Any = None
_original_connect_ex: Any = None
_original_sendto: Any = None
_original_sendmsg: Any = None


def _is_local(address: object) -> bool:
    """True for loopback TCP/UDP targets and any AF_UNIX (filesystem) socket."""
    if not isinstance(address, tuple) or not address:
        # AF_UNIX addresses are str/bytes paths — always local.
        return True
    host = str(address[0])
    if host in _LOOPBACK_HOSTS:
        return True
    # cover 127.0.0.0/8 and IPv4-mapped loopback without importing ipaddress
    return host.startswith("127.") or host.startswith("::ffff:127.")


def _block(address: object) -> None:
    """Raise if ``address`` is a non-loopback target."""
    if not _is_local(address):
        raise NetworkAccessError(
            f"outbound network to {address!r} blocked by SafeStream's offline guard "
            "(pass --allow-network / call netguard.uninstall() to allow)"
        )


def install() -> None:
    """Block outbound non-loopback traffic process-wide. Idempotent.

    Patches the connection-oriented calls (``connect``/``connect_ex``) *and* the
    connectionless datagram calls (``sendto``/``sendmsg``), so a UDP payload sent
    without a prior ``connect`` — statsd/telemetry libraries, custom exfil — is
    stopped too, not just TCP dials.

    Caveat: DNS resolution via ``socket.getaddrinfo`` happens in C and can leak a
    hostname before any socket call, and guarding it would also break loopback
    name resolution; the pure-Python guard does not cover it. Use ``--offline-hard``
    (a network namespace or a seccomp filter) for a kernel-level boundary that
    also stops DNS. See ``netguard_hard`` and ``SECURITY.md``.
    """
    global _original_connect, _original_connect_ex, _original_sendto, _original_sendmsg
    if _original_connect is not None:
        return
    _original_connect = socket.socket.connect
    _original_connect_ex = socket.socket.connect_ex
    _original_sendto = socket.socket.sendto
    _original_sendmsg = socket.socket.sendmsg

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        _block(address)
        return _original_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
        _block(address)
        return _original_connect_ex(self, address)

    def guarded_sendto(self: socket.socket, data: Any, *args: Any) -> Any:
        # sendto(data, address) or sendto(data, flags, address): the destination
        # is always the last positional argument. A connected UDP socket calls
        # sendto without an address (args empty); nothing to guard there.
        if args:
            _block(args[-1])
        return _original_sendto(self, data, *args)

    def guarded_sendmsg(
        self: socket.socket,
        buffers: Any,
        ancdata: Any = (),
        flags: int = 0,
        address: Any = None,
    ) -> Any:
        # sendmsg(buffers, ancdata, flags, address): guard the explicit
        # destination when one is given (unconnected datagram send).
        if address is not None:
            _block(address)
        return _original_sendmsg(self, buffers, ancdata, flags, address)

    socket.socket.connect = guarded_connect  # type: ignore[assignment,method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[assignment,method-assign]
    socket.socket.sendto = guarded_sendto  # type: ignore[assignment,method-assign]
    socket.socket.sendmsg = guarded_sendmsg  # type: ignore[assignment,method-assign]


def uninstall() -> None:
    """Restore the original socket behaviour. Idempotent."""
    global _original_connect, _original_connect_ex, _original_sendto, _original_sendmsg
    if _original_connect is not None:
        socket.socket.connect = _original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _original_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = _original_sendto  # type: ignore[method-assign]
        socket.socket.sendmsg = _original_sendmsg  # type: ignore[method-assign]
        _original_connect = None
        _original_connect_ex = None
        _original_sendto = None
        _original_sendmsg = None


def is_installed() -> bool:
    return _original_connect is not None


@contextmanager
def enforced() -> Iterator[None]:
    """Context manager that guards network access for its duration."""
    already = is_installed()
    install()
    try:
        yield
    finally:
        if not already:
            uninstall()
