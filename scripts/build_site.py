"""Build the static demo site (site/) into a directory GitHub Pages can serve.

    python scripts/build_site.py              # writes _site/
    python scripts/build_site.py --out DIR

The output is self-contained: the page, the safestream_redactor wheel built from
this checkout, and a pinned Pyodide runtime (CPython for WebAssembly), all served
from one origin so the page's Content-Security-Policy can forbid every other one.
Pyodide is fetched from the npm registry once and checked against a pinned hash.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYODIDE_VERSION = "314.0.7"  # CPython 3.14
PYODIDE_URL = f"https://registry.npmjs.org/pyodide/-/pyodide-{PYODIDE_VERSION}.tgz"
# `npm view pyodide@314.0.7 dist.integrity`
PYODIDE_SHA512 = (
    "0YvXxEhfEdpLfb/XkM2BFAeMROq0iMUX2bzzH9pOttyMcWkwq+HbE5uyuGD82LN7y2q+SNvi/6V5JEsOlD2R1A=="
)
# what the worker loads; the rest of the npm package (types, maps, consoles) is not served
PYODIDE_FILES = (
    "pyodide.mjs",
    "pyodide.asm.mjs",
    "pyodide.asm.wasm",
    "python_stdlib.zip",
    "pyodide-lock.json",
)
SITE_FILES = ("index.html", "style.css", "app.js", "engine.js", "engine.py", "favicon.svg")


def fetch_pyodide(dest: Path) -> None:
    with urllib.request.urlopen(PYODIDE_URL, timeout=120) as resp:
        data = resp.read()
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    if digest != PYODIDE_SHA512:
        raise SystemExit(f"build_site: Pyodide tarball hash mismatch ({digest})")
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for name in PYODIDE_FILES:
            member = tar.extractfile(f"package/{name}")
            if member is None:
                raise SystemExit(f"build_site: {name} missing from the Pyodide package")
            (dest / name).write_bytes(member.read())


def build_wheel(dest: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", tmp, str(ROOT)],
            check=True,
        )
        (wheel,) = Path(tmp).glob("safestream_redactor-*.whl")
        dest.mkdir(parents=True)
        # a fixed name, so the page never needs to know the version to load it
        shutil.copy(wheel, dest / "safestream_redactor.whl")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "_site")
    out = parser.parse_args().out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in SITE_FILES:
        shutil.copy(ROOT / "site" / name, out / name)
    build_wheel(out / "engine")
    fetch_pyodide(out / "pyodide")
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"site built in {out} ({size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
