"""Network-egress guard tests."""

import socket

import pytest

from safestream_redactor import netguard


@pytest.fixture(autouse=True)
def _clean():
    netguard.uninstall()
    yield
    netguard.uninstall()


def test_not_installed_on_import():
    assert not netguard.is_installed()


def test_blocks_external_connection():
    netguard.install()
    with pytest.raises(netguard.NetworkAccessError):
        socket.socket().connect(("8.8.8.8", 53))


def test_allows_loopback():
    netguard.install()
    # loopback must never raise NetworkAccessError (a refused/timeout OSError is fine)
    with pytest.raises(OSError) as exc:
        socket.create_connection(("127.0.0.1", 9), timeout=0.2)
    assert not isinstance(exc.value, netguard.NetworkAccessError)


def test_context_manager_restores():
    assert not netguard.is_installed()
    with netguard.enforced():
        assert netguard.is_installed()
    assert not netguard.is_installed()


def test_install_is_idempotent():
    netguard.install()
    first = socket.socket.connect
    netguard.install()
    assert socket.socket.connect is first


def test_is_local_classification():
    assert netguard._is_local(("127.0.0.1", 80))
    assert netguard._is_local(("localhost", 80))
    assert netguard._is_local("/var/run/socket")  # AF_UNIX path
    assert not netguard._is_local(("93.184.216.34", 443))
