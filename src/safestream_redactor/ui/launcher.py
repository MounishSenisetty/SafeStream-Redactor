"""Start the web playground with privacy-preserving Streamlit settings.

``safestream ui`` (or ``python -m safestream_redactor.ui``) runs Streamlit in a
child process with the settings this tool's local-only promise depends on,
none of which are Streamlit's defaults:

* ``--server.address 127.0.0.1`` — Streamlit otherwise listens on every
  network interface, exposing the page (and whatever is pasted into it) to the
  local network;
* ``--browser.gatherUsageStats false`` — Streamlit otherwise sends usage
  statistics from the browser;
* ``--server.maxUploadSize`` — Streamlit otherwise buffers uploads of up to
  200 MB in memory before the page can refuse them.
* ``--client.toolbarMode minimal`` — hides the toolbar's "Deploy" button, which
  would publish the page to Streamlit Community Cloud.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

from safestream_redactor.ui.core import MAX_INPUT_BYTES

APP_PATH = Path(__file__).with_name("app.py")
INSTALL_HINT = (
    "The web UI needs the optional 'ui' extra (Streamlit), which is not installed.\n"
    "Install it with:  pip install 'safestream-redactor[ui]'"
)
# Streamlit's upload cap is in whole megabytes; round the playground's cap up so
# a file the page accepts is never refused by the server first.
MAX_UPLOAD_MB = -(-MAX_INPUT_BYTES // (1024 * 1024))


def streamlit_available() -> bool:
    return importlib.util.find_spec("streamlit") is not None


def build_command(
    host: str = "127.0.0.1", port: int = 8501, *, headless: bool = False
) -> list[str]:
    """The ``streamlit run`` invocation for the playground."""
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(APP_PATH),
        "--server.address",
        host,
        "--server.port",
        str(port),
        "--server.headless",
        "true" if headless else "false",
        "--server.maxUploadSize",
        str(MAX_UPLOAD_MB),
        "--browser.gatherUsageStats",
        "false",
        # hides Streamlit's "Deploy" button, which offers to publish the page to
        # Streamlit Community Cloud: the opposite of a local-only tool
        "--client.toolbarMode",
        "minimal",
        # no file watcher: the installed package is not edited while it runs
        "--server.fileWatcherType",
        "none",
    ]


def launch(host: str = "127.0.0.1", port: int = 8501, *, headless: bool = False) -> int:
    """Run the playground until interrupted. Returns the process exit status."""
    if not streamlit_available():
        print(f"safestream: error: {INSTALL_HINT}", file=sys.stderr)
        return 1
    print(f"-- SafeStream web UI on http://{host}:{port} (Ctrl-C to stop)", file=sys.stderr)
    try:
        return subprocess.call(build_command(host, port, headless=headless))
    except KeyboardInterrupt:  # Ctrl-C reaches the child too; exit quietly
        return 0
