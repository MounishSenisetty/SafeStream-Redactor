"""The pre-commit hook and GitHub Action definitions parse and wire correctly."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from safestream_redactor.cli import main

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parent.parent


def test_pre_commit_hook_definition_valid() -> None:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    assert isinstance(hooks, list)
    hook = next(h for h in hooks if h["id"] == "safestream-detect")
    # The hook must invoke the fail-on-detect gate so a secret blocks the commit.
    assert "detect" in hook["entry"]
    assert "--fail-on-detect" in hook["entry"]
    assert hook["language"] == "python"


def test_github_action_definition_valid() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    joined = "\n".join(step.get("run", "") for step in steps)
    assert "--fail-on-detect" in joined
    assert "safestream detect" in joined


def test_detect_multiple_files_gate(tmp_path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here\n")
    dirty = tmp_path / "dirty.env"
    dirty.write_text("aws AKIAIOSFODNN7EXAMPLE\n")
    # A single clean file passes the gate.
    assert main(["detect", str(clean), "--fail-on-detect"]) == 0
    # A batch containing one dirty file fails the gate (pre-commit semantics).
    assert main(["detect", str(clean), str(dirty), "--fail-on-detect"]) == 1


def test_pre_commit_hook_never_prints_matched_text() -> None:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    hook = next(h for h in hooks if h["id"] == "safestream-detect")
    assert "--hide-text" in hook["entry"]


def test_action_never_interpolates_inputs_into_scripts() -> None:
    # ${{ inputs.* }} inside `run:` is spliced into the script before bash
    # parses it (script injection); inputs must arrive via `env:` instead.
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    for step in action["runs"]["steps"]:
        assert "${{" not in step.get("run", ""), step["name"]


def _action_scan_script() -> str:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    step = next(s for s in action["runs"]["steps"] if s["name"] == "Scan for secrets and PII")
    return str(step["run"])


@pytest.mark.skipif(
    os.name == "nt" or not shutil.which("bash") or not shutil.which("safestream"),
    reason="runs the composite step with bash and the installed console script",
)
@pytest.mark.parametrize("with_sarif", [False, True])
def test_action_scan_step_end_to_end(tmp_path, with_sarif) -> None:
    # Executes the Action's real script, as GitHub runs a composite bash step.
    # The default input is a directory ('.'), which used to fail on every run.
    secret = "AKIAIOSFODNN7EXAMPLE"
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "settings.env").write_text(f"AWS_KEY={secret}\n")
    sarif = tmp_path / "out.sarif"
    env = {
        **os.environ,
        "SCAN_PATHS": ".",
        "SCAN_CONFIG": "",
        "SARIF_FILE": str(sarif) if with_sarif else "",
    }
    script = _action_scan_script()
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 1, proc.stderr  # the finding fails the build
    assert "app/settings.env:1:9: aws_key" in proc.stdout
    assert secret not in proc.stdout + proc.stderr  # never echoed into the log
    if with_sarif:
        assert secret not in sarif.read_text()
        assert json.loads(sarif.read_text())["runs"][0]["results"]

    (repo / "app" / "settings.env").write_text("AWS_KEY=from-vault\n")
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(
    os.name == "nt" or not shutil.which("bash") or not shutil.which("safestream"),
    reason="runs the composite step with bash and the installed console script",
)
def test_action_paths_glob_but_never_execute(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.env").write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    canary = tmp_path / "pwned"
    env = {
        **os.environ,
        # a glob (must expand) followed by a command substitution (must not run)
        "SCAN_PATHS": f"*.env $(touch {canary})",
        "SCAN_CONFIG": "",
        "SARIF_FILE": "",
    }
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", _action_scan_script()],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert not canary.exists()
    assert "a.env:1:9: aws_key" in proc.stdout  # the glob expanded to the file
