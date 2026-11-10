"""Check an *installed* safestream-redactor, the way a user would get it.

    python scripts/smoke_test.py                 # base install
    python scripts/smoke_test.py --native        # + the [native] extra is active
    python scripts/smoke_test.py --crypto --ui   # + the [crypto] / [ui] extras work

CI runs this against the built wheel, the sdist and the TestPyPI upload on every
OS. Run it from a fresh virtualenv, not an editable install, to test what ships.
Exits non-zero, with the failing check named, on the first failure.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request
import warnings
from pathlib import Path

SAMPLE = "user=bob@corp.example ssn: 123-45-6789 key=AKIAIOSFODNN7EXAMPLE\n"
EXPECTED = "user=[REDACTED] ssn: [REDACTED] key=[REDACTED]\n"
# a broader sample for the native-vs-Python identity check
MIXED = (
    "Maria Garcia <maria.garcia@corpmail.com> called +1 415 555 0132 from 10.20.30.40.\n"
    "Card 4111 1111 1111 1111, token ghp_1234567890abcdefghijklmnopqrstuvwxyz, "
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
)
BIN = Path(sys.executable).parent  # the console scripts sit next to the interpreter


def check(name: str, ok: bool, detail: object = "") -> None:
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and not ok else ""))
    if not ok:
        raise SystemExit(1)


def run(*args: str, stdin: str = "") -> str:
    out = subprocess.run(args, input=stdin.encode(), capture_output=True, check=False)
    command = " ".join([Path(args[0]).name, *args[1:]])
    check(f"`{command}` exits 0", out.returncode == 0, out.stderr.decode(errors="replace"))
    return out.stdout.decode()


def base() -> None:
    import safestream_redactor as pkg
    from safestream_redactor import Redactor

    check("import from site-packages", "site-packages" in pkg.__file__, pkg.__file__)
    check("library redact", Redactor().redact(SAMPLE) == EXPECTED, Redactor().redact(SAMPLE))
    for script in ("safestream", "safestream-redactor"):
        exe = next((p for p in BIN.glob(f"{script}*") if p.stem == script), None)
        check(f"console script {script}", exe is not None, BIN)
        version = run(str(exe), "--version")
        check(f"{script} --version", pkg.__version__ in version, version)
    out = run(str(BIN / "safestream"), "redact", "-", "-o", "-", stdin=SAMPLE)
    check("CLI redact stdin -> stdout", out.replace("\r\n", "\n") == EXPECTED, repr(out))


def native() -> None:
    from importlib.metadata import version

    from safestream_redactor import Redactor, __version__
    from safestream_redactor.detectors.deterministic import DeterministicDetector

    # the distribution version: the module's __version__ is the crate's semver form
    native_version = version("safestream-redactor-native")
    check("native version matches", native_version == __version__, native_version)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # a fallback warning means native is not in use
        check("native core active", DeterministicDetector(backend="native")._native is not None)
        fast = Redactor(backend="native").redact(MIXED)
    check("native output identical to Python", fast == Redactor().redact(MIXED), fast)


def crypto() -> None:
    from safestream_redactor import Deanonymizer, RedactionPolicy, Redactor

    key = "k" * 32
    sealed = Redactor(policy=RedactionPolicy(mode="encrypt", encrypt_key=key)).redact(SAMPLE)
    check("encrypt hides values", "bob@corp.example" not in sealed, sealed)
    check("deanonymize restores", Deanonymizer(key).restore(sealed) == SAMPLE)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    # `safestream ui` runs Streamlit as a child: stop both, or the child outlives us
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        os.killpg(proc.pid, signal.SIGTERM)
    proc.wait(timeout=30)


def ui(port: int = 8597) -> None:
    server = subprocess.Popen(
        [str(BIN / "safestream"), "ui", "--headless", "--port", str(port)],
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        start_new_session=sys.platform != "win32",  # its own process group, for killpg
    )
    url = f"http://127.0.0.1:{port}/_stcore/health"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and server.poll() is None:
            try:
                with opener.open(url, timeout=2) as resp:
                    check("safestream ui answers its health check", resp.status == 200)
                    return
            except OSError:
                time.sleep(0.5)
        check("safestream ui answers its health check", False, f"exit={server.poll()}")
    finally:
        _kill_tree(server)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for flag in ("native", "crypto", "ui"):
        parser.add_argument(f"--{flag}", action="store_true", help=f"also check the [{flag}] extra")
    opts = parser.parse_args()
    base()
    for flag in ("native", "crypto", "ui"):
        if getattr(opts, flag):
            globals()[flag]()
    print("smoke test passed")
