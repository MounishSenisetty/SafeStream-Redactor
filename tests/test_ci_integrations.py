"""The pre-commit hook and GitHub Action definitions parse and wire correctly."""

from __future__ import annotations

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
