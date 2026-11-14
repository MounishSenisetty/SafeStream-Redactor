"""Set the release version of both distributions in one step.

    python scripts/set_version.py 0.5.1        # a release
    python scripts/set_version.py 0.5.1.dev42  # a TestPyPI dry run (CI does this)

The package and the optional Rust core in ``native/`` share one version, so it
is written to every place that carries it:

* ``src/safestream_redactor/__init__.py``  ``__version__`` (PEP 440)
* ``native/Cargo.toml`` and ``native/Cargo.lock``  the crate version (semver;
  maturin converts ``0.5.1-dev42`` back to ``0.5.1.dev42`` for the wheel)

``tests/test_packaging.py`` fails if they ever disagree.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# X.Y.Z with an optional aN / bN / rcN / .devN suffix: the forms both PEP 440
# and maturin's semver conversion agree on
VERSION = re.compile(r"^(\d+\.\d+\.\d+)\.?((?:a|b|rc|dev)\d+)?$")


def cargo_version(version: str) -> str:
    match = VERSION.match(version)
    if not match:
        raise ValueError(f"unsupported version {version!r}: use X.Y.Z[aN|bN|rcN|.devN]")
    base, suffix = match.groups()
    return f"{base}-{suffix}" if suffix else base


def _sub(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if n != 1:
        raise SystemExit(f"set_version: pattern not found in {path.relative_to(ROOT)}")
    path.write_text(new, encoding="utf-8")


def set_version(version: str) -> None:
    crate = cargo_version(version)
    _sub(
        ROOT / "src/safestream_redactor/__init__.py",
        r'^__version__ = ".*"$',
        f'__version__ = "{version}"',
    )
    _sub(ROOT / "native/Cargo.toml", r'^version = ".*"$', f'version = "{crate}"')
    _sub(
        ROOT / "native/Cargo.lock", r'(name = "safestream_native"\nversion = )".*"', rf'\1"{crate}"'
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    set_version(sys.argv[1])
    print(f"version set to {sys.argv[1]} (crate {cargo_version(sys.argv[1])})")
