"""README.md is also the PyPI page: its examples must run, and it must render there.

* ``console`` blocks: each ``$ command`` runs in a shared temporary directory, and its
  output must equal the lines shown under it. ``pip``/``pipx`` lines are not run.
* ``python`` blocks: executed in the same directory, in order. ``expr  # -> value``
  (or ``# -> value`` on the line after ``expr``) asserts ``repr(expr) == value``.
* No relative links or images (they break on PyPI) and no Mermaid (PyPI shows source).
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

README = Path(__file__).resolve().parent.parent / "README.md"
TEXT = README.read_text(encoding="utf-8")
BLOCK = re.compile(r"^```(\w*)\n(.*?)^```", re.M | re.S)
NOT_RUN = ("pip ", "pipx ")


def blocks(lang: str) -> list[str]:
    return [body for kind, body in BLOCK.findall(TEXT) if kind == lang]


def console_steps() -> list[tuple[str, str]]:
    steps: list[tuple[str, list[str]]] = []
    for body in blocks("console"):
        for line in body.splitlines():
            if line.startswith("$ "):
                steps.append((line[2:], []))
            else:
                steps[-1][1].append(line)
    return [(cmd, "".join(f"{line}\n" for line in out)) for cmd, out in steps]


def python_source(body: str) -> str:
    lines = body.splitlines()
    out: list[str] = []
    for line in lines:
        if line.startswith("# -> "):  # asserts the expression on the previous line
            out[-1] = f"assert repr({out[-1]}) == {line[5:]!r}, repr({out[-1]})"
        elif (m := re.match(r"^(\S.*?)\s+# -> (.*)$", line)) and not line.startswith("#"):
            out.append(f"assert repr({m[1]}) == {m[2]!r}, repr({m[1]})")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("readme")


@pytest.mark.skipif(shutil.which("bash") is None or sys.platform == "win32", reason="POSIX shell")
def test_console_examples_produce_the_output_shown(workdir: Path) -> None:
    steps = console_steps()
    assert steps, "README has no console examples"
    # the `safestream` that belongs to the interpreter running the tests
    env = {**os.environ, "PATH": f"{sysconfig.get_path('scripts')}{os.pathsep}{os.environ['PATH']}"}
    for cmd, expected in steps:
        if cmd.startswith(NOT_RUN):
            assert not expected, f"output shown for a command that is not run: {cmd}"
            continue
        done = subprocess.run(
            ["bash", "-c", cmd], cwd=workdir, env=env, capture_output=True, text=True
        )
        # `detect` reports to stdout and its summary line to stderr; show both, in order
        shown = done.stdout + done.stderr
        assert done.returncode == 0, f"$ {cmd}\n{shown}"
        assert shown == expected, f"$ {cmd}\n--- README shows:\n{expected}--- actual:\n{shown}"


def test_python_examples_run_and_print_what_they_claim(workdir: Path) -> None:
    sources = [python_source(b) for b in blocks("python")]
    assert sources, "README has no python examples"
    if not (workdir / "app.log").exists():  # the console test creates it on POSIX
        pytest.skip("needs the app.log the console examples create")
    cwd = os.getcwd()
    os.chdir(workdir)
    try:
        for source in sources:
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(source, str(README), "exec"), {"__name__": "readme"})
    finally:
        os.chdir(cwd)


def test_renders_on_pypi() -> None:
    links = re.findall(r"\]\(([^)\s]+)", TEXT)
    relative = [u for u in links if not u.startswith(("https://", "http://", "#", "mailto:"))]
    assert not relative, f"relative links break on the PyPI page: {relative}"
    assert "```mermaid" not in TEXT, "PyPI shows Mermaid diagrams as source"
    # `#user-content-x`: the id both GitHub and PyPI's renderer give a heading
    anchors = {u.removeprefix("#user-content-") for u in links if u.startswith("#")}
    assert all(u.startswith("#user-content-") for u in links if u.startswith("#")), (
        "in-page links must use #user-content-<heading>; PyPI ids carry that prefix"
    )
    headings = {
        re.sub(r"[^\w\- ]", "", h).strip().lower().replace(" ", "-")
        for h in re.findall(r"^#+ (.+)$", TEXT, re.M)
    }
    assert anchors <= headings, f"links to missing sections: {anchors - headings}"
