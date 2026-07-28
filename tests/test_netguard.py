"""Network-egress guard tests."""

import socket

import pytest

from safestream_redactor import netguard


@pytest.fixture(autouse=True)
def _clean():
    # fully drain the install refcount before and after each test
    while netguard.is_installed():
        netguard.uninstall()
    yield
    while netguard.is_installed():
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


def test_install_patches_once():
    netguard.install()
    first = socket.socket.connect
    netguard.install()
    assert socket.socket.connect is first  # patched once regardless of count
    netguard.uninstall()  # balance the two installs
    netguard.uninstall()


def test_refcount_survives_nested_enforced():
    # the inner block leaving must not drop the guard the outer block relies on
    with netguard.enforced():
        with netguard.enforced():
            assert netguard.is_installed()
        # inner exited, but outer still needs the guard active
        assert netguard.is_installed()
        with pytest.raises(netguard.NetworkAccessError):
            socket.socket().connect(("8.8.8.8", 53))
    assert not netguard.is_installed()


def test_concurrent_enforced_keeps_guard_until_last_leaves():
    import threading

    start = threading.Barrier(2)
    release_first = threading.Event()
    second_saw_guard = []

    def worker_short():
        with netguard.enforced():
            start.wait()
            release_first.wait(2)  # leave while the other thread is still inside

    def worker_long():
        with netguard.enforced():
            start.wait()
            release_first.set()
            # the short worker has now exited its enforced() block; a boolean
            # flag would have dropped the guard here — the refcount must not
            second_saw_guard.append(netguard.is_installed())

    t1, t2 = threading.Thread(target=worker_short), threading.Thread(target=worker_long)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert second_saw_guard == [True]
    assert not netguard.is_installed()


def test_is_local_classification():
    assert netguard._is_local(("127.0.0.1", 80))
    assert netguard._is_local(("localhost", 80))
    assert netguard._is_local("/var/run/socket")  # AF_UNIX path
    assert not netguard._is_local(("93.184.216.34", 443))
