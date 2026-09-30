"""The `safestream ui` launcher: install hint, Streamlit flags, CLI wiring."""

from __future__ import annotations

import runpy
from typing import ClassVar

import pytest

from safestream_redactor.cli import main
from safestream_redactor.ui import launcher


def _flag(cmd: list[str], name: str) -> str:
    return cmd[cmd.index(name) + 1]


class _FakeServer:
    """Stands in for the Streamlit child process."""

    started: ClassVar[list[list[str]]] = []

    def __init__(self, cmd: list[str], returncode: int = 0) -> None:
        _FakeServer.started.append(cmd)
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode

    def wait(self) -> int:
        return self.returncode


@pytest.fixture
def fake_streamlit(monkeypatch):
    _FakeServer.started = []
    opened: list[str] = []
    monkeypatch.setattr(launcher, "streamlit_available", lambda: True)
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakeServer)
    monkeypatch.setattr(launcher, "_open_when_ready", lambda url, server: opened.append(url))
    return opened


def test_missing_extra_prints_install_hint(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: False)
    monkeypatch.setattr(launcher.subprocess, "Popen", pytest.fail)  # never started
    assert main(["ui"]) == 1
    err = capsys.readouterr().err
    assert "pip install 'safestream-redactor[ui]'" in err


def test_command_enforces_local_only_settings():
    cmd = launcher.build_command()
    assert cmd[1:4] == ["-m", "streamlit", "run"]
    assert cmd[4] == str(launcher.APP_PATH) and launcher.APP_PATH.is_file()
    assert _flag(cmd, "--server.address") == "127.0.0.1"
    assert _flag(cmd, "--browser.gatherUsageStats") == "false"
    assert _flag(cmd, "--client.toolbarMode") == "minimal"  # no "Deploy" button
    # always headless: otherwise Streamlit's first run blocks on an "Email:" prompt
    assert _flag(cmd, "--server.headless") == "true"
    # the server refuses anything the page would refuse, before buffering it
    assert int(_flag(cmd, "--server.maxUploadSize")) * 1024 * 1024 >= launcher.MAX_INPUT_BYTES
    assert int(_flag(cmd, "--server.maxUploadSize")) == 5


def test_cli_passes_options_through_and_opens_browser(fake_streamlit, capsys):
    assert main(["ui", "--port", "9123"]) == 0
    (cmd,) = _FakeServer.started
    assert _flag(cmd, "--server.port") == "9123"
    assert fake_streamlit == ["http://127.0.0.1:9123"]
    err = capsys.readouterr().err
    assert "http://127.0.0.1:9123" in err and "warning" not in err


def test_headless_flag_skips_the_browser(fake_streamlit):
    assert main(["ui", "--headless"]) == 0
    assert fake_streamlit == []


def test_cli_warns_on_non_loopback_host(fake_streamlit, capsys):
    assert main(["ui", "--host", "0.0.0.0"]) == 0
    assert "beyond this machine" in capsys.readouterr().err
    assert fake_streamlit == ["http://127.0.0.1:8501"]  # a wildcard is browsed via loopback


@pytest.mark.parametrize(
    ("host", "url"),
    [
        ("127.0.0.1", "http://127.0.0.1:8501"),
        ("0.0.0.0", "http://127.0.0.1:8501"),
        ("::", "http://127.0.0.1:8501"),
        ("::1", "http://[::1]:8501"),
        ("localhost", "http://localhost:8501"),
    ],
)
def test_browse_url(host, url):
    assert launcher.browse_url(host, 8501) == url


def test_child_exit_status_is_returned(monkeypatch, fake_streamlit):
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda cmd: _FakeServer(cmd, 3))
    assert launcher.launch() == 3


def test_ctrl_c_waits_for_the_server_to_stop(monkeypatch, fake_streamlit):
    class _Interrupted(_FakeServer):
        calls = 0

        def wait(self) -> int:
            _Interrupted.calls += 1
            if _Interrupted.calls == 1:
                raise KeyboardInterrupt
            return 0

    monkeypatch.setattr(launcher.subprocess, "Popen", _Interrupted)
    assert launcher.launch() == 0
    assert _Interrupted.calls == 2  # it waited for the child after the interrupt


def test_browser_opens_only_after_the_server_is_healthy(monkeypatch):
    opened, attempts = [], []

    class _Opener:
        def open(self, url, timeout):
            attempts.append(url)
            if len(attempts) < 3:
                raise OSError("connection refused")  # not up yet

            class _Response:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            return _Response()

    class _Running:
        def poll(self):
            return None

    monkeypatch.setattr(launcher.urllib.request, "build_opener", lambda *handlers: _Opener())
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    monkeypatch.setattr(launcher.time, "sleep", lambda s: None)
    launcher._open_when_ready("http://127.0.0.1:8501", _Running())
    assert attempts == ["http://127.0.0.1:8501/_stcore/health"] * 3
    assert opened == ["http://127.0.0.1:8501"]


def test_browser_not_opened_if_the_server_exits(monkeypatch):
    opened = []

    class _Exited:
        def poll(self):
            return 1

    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    launcher._open_when_ready("http://127.0.0.1:8501", _Exited())
    assert opened == []


def test_python_dash_m_entry_point(monkeypatch):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: False)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("safestream_redactor.ui", run_name="__main__")
    assert exc.value.code == 1


def test_streamlit_available_reflects_the_environment(monkeypatch):
    monkeypatch.setattr(launcher.importlib.util, "find_spec", lambda name: None)
    assert launcher.streamlit_available() is False
