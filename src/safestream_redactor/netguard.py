"""Runtime network-egress guard — *enforce* the offline privacy guarantee.

SafeStream's promise is that sensitive text never leaves the machine. This
module makes that enforceable rather than merely documented: once installed, it
monkeypatches the socket layer so any attempt to open a connection to a
non-loopback address raises :class:`NetworkAccessError` before a single byte is
sent.

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


def install() -> None:
    """Block outbound non-loopback connections process-wide. Idempotent."""
    global _original_connect, _original_connect_ex
    if _original_connect is not None:
        return
    _original_connect = socket.socket.connect
    _original_connect_ex = socket.socket.connect_ex

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if not _is_local(address):
            raise NetworkAccessError(
                f"outbound network connection to {address!r} blocked by SafeStream's "
                "offline guard (pass --allow-network / call netguard.uninstall() to allow)"
            )
        return _original_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
        if not _is_local(address):
            raise NetworkAccessError(
                f"outbound network connection to {address!r} blocked by SafeStream's offline guard"
            )
        return _original_connect_ex(self, address)

    socket.socket.connect = guarded_connect  # type: ignore[assignment,method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[assignment,method-assign]


def uninstall() -> None:
    """Restore the original socket behaviour. Idempotent."""
    global _original_connect, _original_connect_ex
    if _original_connect is not None:
        socket.socket.connect = _original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _original_connect_ex  # type: ignore[method-assign]
        _original_connect = None
        _original_connect_ex = None


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
