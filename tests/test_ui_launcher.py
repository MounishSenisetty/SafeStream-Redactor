"""The `safestream ui` launcher: install hint, Streamlit flags, CLI wiring."""

from __future__ import annotations

import runpy

import pytest

from safestream_redactor.cli import main
from safestream_redactor.ui import launcher


def _flag(cmd: list[str], name: str) -> str:
    return cmd[cmd.index(name) + 1]


def test_missing_extra_prints_install_hint(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: False)
    monkeypatch.setattr(launcher.subprocess, "call", pytest.fail)  # never started
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
    assert _flag(cmd, "--server.headless") == "false"
    # the server refuses anything the page would refuse, before buffering it
    assert int(_flag(cmd, "--server.maxUploadSize")) * 1024 * 1024 >= launcher.MAX_INPUT_BYTES
    assert int(_flag(cmd, "--server.maxUploadSize")) == 5


def test_cli_passes_options_through(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(launcher, "streamlit_available", lambda: True)
    monkeypatch.setattr(launcher.subprocess, "call", lambda cmd: calls.append(cmd) or 0)
    assert main(["ui", "--port", "9123", "--headless"]) == 0
    (cmd,) = calls
    assert _flag(cmd, "--server.port") == "9123"
    assert _flag(cmd, "--server.headless") == "true"
    err = capsys.readouterr().err
    assert "http://127.0.0.1:9123" in err and "warning" not in err


def test_cli_warns_on_non_loopback_host(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: True)
    monkeypatch.setattr(launcher.subprocess, "call", lambda cmd: 0)
    assert main(["ui", "--host", "0.0.0.0"]) == 0
    assert "beyond this machine" in capsys.readouterr().err


def test_child_exit_status_is_returned(monkeypatch):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: True)
    monkeypatch.setattr(launcher.subprocess, "call", lambda cmd: 3)
    assert launcher.launch() == 3


def test_ctrl_c_exits_cleanly(monkeypatch):
    def _interrupt(cmd):
        raise KeyboardInterrupt

    monkeypatch.setattr(launcher, "streamlit_available", lambda: True)
    monkeypatch.setattr(launcher.subprocess, "call", _interrupt)
    assert launcher.launch() == 0


def test_python_dash_m_entry_point(monkeypatch):
    monkeypatch.setattr(launcher, "streamlit_available", lambda: False)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("safestream_redactor.ui", run_name="__main__")
    assert exc.value.code == 1


def test_streamlit_available_reflects_the_environment(monkeypatch):
    monkeypatch.setattr(launcher.importlib.util, "find_spec", lambda name: None)
    assert launcher.streamlit_available() is False
