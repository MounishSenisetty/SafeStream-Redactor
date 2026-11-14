"""The two distributions stay in lockstep (see scripts/set_version.py)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from safestream_redactor import __version__

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 only
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("set_version", ROOT / "scripts/set_version.py")
assert _spec and _spec.loader
set_version = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(set_version)


def _toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text(encoding="utf-8"))


def test_native_crate_version_matches_package():
    crate = _toml("native/Cargo.toml")["package"]["version"]
    assert crate == set_version.cargo_version(__version__)
    lock = _toml("native/Cargo.lock")["package"]
    assert [p["version"] for p in lock if p["name"] == "safestream_native"] == [crate]


def test_native_license_is_a_copy_of_the_root_license():
    # maturin cannot package a file outside native/, so the wheel ships a copy
    assert (ROOT / "native/LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


@pytest.mark.parametrize(
    ("pep440", "semver"),
    [("0.5.1", "0.5.1"), ("0.5.1rc1", "0.5.1-rc1"), ("1.0.0.dev42", "1.0.0-dev42")],
)
def test_cargo_version_mapping(pep440, semver):
    # maturin maps these semver pre-releases back to the same PEP 440 string
    assert set_version.cargo_version(pep440) == semver


@pytest.mark.parametrize("bad", ["0.5", "0.5.1-rc1", "0.5.1+local", "v0.5.1", "0.5.1.post1"])
def test_cargo_version_rejects_unmappable(bad):
    with pytest.raises(ValueError, match="unsupported version"):
        set_version.cargo_version(bad)
