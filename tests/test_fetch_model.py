"""Tests for the opt-in model fetcher (``safestream fetch-model`` / ``fetch_model``).

A local loopback HTTP server stands in for the release host, so no real network
is touched. The archives hold the tiny fixture model from the ONNX inference
tests, so a successful fetch is also checked to make the tier auto-enable.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import tarfile
import threading
from pathlib import Path

import pytest

from safestream_redactor.models import (
    DEFAULT_MODEL,
    ModelVerificationError,
    fetch_model,
)

# The fixture model builder needs onnx; the pure fetch/verify tests do not, so
# import lazily inside the fixtures that need a loadable model.
_VOCAB = {
    "<unk>": 0, "john": 1, "smith": 2, "works": 3, "at": 4,
    "acme": 5, "corp": 6, "in": 7, "paris": 8,
}  # fmt: skip
_ID2LABEL = {0: "O", 1: "B-PER", 2: "I-PER", 3: "B-ORG", 4: "I-ORG", 5: "B-LOC", 6: "I-LOC"}


def _write_dummy_model_files(d: Path) -> None:
    """Minimal, non-loadable stand-ins: enough to exercise download/verify/unpack."""
    (d / "model.int8.onnx").write_bytes(b"\x00onnx-placeholder")
    (d / "vocab.json").write_text(json.dumps(_VOCAB), encoding="utf-8")
    (d / "labels.json").write_text(
        json.dumps({str(k): v for k, v in _ID2LABEL.items()}), encoding="utf-8"
    )


def _make_archive(path: Path, files: dict[str, bytes]) -> str:
    with tarfile.open(path, "w:gz") as tar:
        for arcname, data in files.items():
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            import io

            tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def served(tmp_path):
    """Serve ``tmp_path`` over loopback HTTP; yields a ``url_for(name)`` helper."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield lambda name: f"http://127.0.0.1:{port}/{name}"
    finally:
        httpd.shutdown()
        thread.join()


@pytest.fixture
def good_archive(tmp_path):
    files = {
        "model.int8.onnx": b"\x00onnx-placeholder",
        "vocab.json": json.dumps(_VOCAB).encode(),
        "labels.json": json.dumps({str(k): v for k, v in _ID2LABEL.items()}).encode(),
    }
    sha = _make_archive(tmp_path / "model.tar.gz", files)
    return "model.tar.gz", sha


def test_fetch_installs_with_correct_checksum(tmp_path, served, good_archive):
    name, sha = good_archive
    dest = tmp_path / "install"
    out = fetch_model(url=served(name), sha256=sha, dest=dest)
    assert out == dest
    assert {p.name for p in dest.iterdir()} == {"model.int8.onnx", "vocab.json", "labels.json"}


def test_fetch_rejects_checksum_mismatch_and_installs_nothing(tmp_path, served, good_archive):
    name, _ = good_archive
    dest = tmp_path / "install"
    with pytest.raises(ModelVerificationError, match="SHA-256 mismatch"):
        fetch_model(url=served(name), sha256="0" * 64, dest=dest)
    assert not dest.exists() or not any(dest.iterdir())


def test_fetch_refuses_without_a_checksum(tmp_path, served, good_archive):
    name, _ = good_archive
    with pytest.raises(ValueError, match="no SHA-256 is pinned"):
        fetch_model(url=served(name), dest=tmp_path / "install")


def test_fetch_allow_unverified_installs_without_checksum(tmp_path, served, good_archive):
    name, _ = good_archive
    dest = tmp_path / "install"
    fetch_model(url=served(name), dest=dest, allow_unverified=True)
    assert (dest / "model.int8.onnx").is_file()


def test_fetch_refuses_overwrite_without_force(tmp_path, served, good_archive):
    name, sha = good_archive
    dest = tmp_path / "install"
    fetch_model(url=served(name), sha256=sha, dest=dest)
    with pytest.raises(FileExistsError, match="--force"):
        fetch_model(url=served(name), sha256=sha, dest=dest)
    # --force replaces it
    fetch_model(url=served(name), sha256=sha, dest=dest, force=True)
    assert (dest / "model.int8.onnx").is_file()


def test_fetch_rejects_archive_missing_model(tmp_path, served):
    sha = _make_archive(tmp_path / "bad.tar.gz", {"labels.json": b"{}"})
    with pytest.raises(ValueError, match="missing a model"):
        fetch_model(url=served("bad.tar.gz"), sha256=sha, dest=tmp_path / "install")


def test_fetch_ignores_unsafe_and_unknown_members(tmp_path, served):
    # path-traversal, absolute and nested members must never be written; only the
    # allow-listed flat basenames land in dest.
    files = {
        "model.int8.onnx": b"\x00m",
        "vocab.json": json.dumps(_VOCAB).encode(),
        "../escape.txt": b"nope",
        "/abs.txt": b"nope",
        "nested/evil.onnx": b"nope",
        "README.md": b"ignored",
    }
    sha = _make_archive(tmp_path / "mix.tar.gz", files)
    dest = tmp_path / "install"
    fetch_model(url=served("mix.tar.gz"), sha256=sha, dest=dest)
    assert {p.name for p in dest.iterdir()} == {"model.int8.onnx", "vocab.json"}
    assert not (tmp_path / "escape.txt").exists()
    assert not (dest.parent / "abs.txt").exists()


def test_fetch_respects_size_cap(tmp_path, served, good_archive, monkeypatch):
    import safestream_redactor.models as models

    name, sha = good_archive
    monkeypatch.setattr(models, "MAX_DOWNLOAD_BYTES", 4)
    with pytest.raises(ValueError, match="exceeds"):
        fetch_model(url=served(name), sha256=sha, dest=tmp_path / "install")


def test_default_model_is_registered_but_unpinned():
    # The mechanism ships ready; the official artifact's digest is pinned by a
    # maintainer once published. Until then an unparameterised fetch refuses.
    assert DEFAULT_MODEL.sha256 is None
    with pytest.raises(ValueError, match="no SHA-256 is pinned"):
        fetch_model()


# --- CLI ---------------------------------------------------------------------


def test_cli_fetch_model_installs(tmp_path, served, good_archive, capsys):
    from safestream_redactor.cli import main

    name, sha = good_archive
    dest = tmp_path / "install"
    rc = main(["fetch-model", "--url", served(name), "--sha256", sha, "--out", str(dest)])
    assert rc == 0
    assert (dest / "model.int8.onnx").is_file()
    assert "installed model into" in capsys.readouterr().err


def test_cli_fetch_model_checksum_mismatch_exits_nonzero(tmp_path, served, good_archive):
    from safestream_redactor.cli import main

    name, _ = good_archive
    with pytest.raises(SystemExit):
        main(["fetch-model", "--url", served(name), "--sha256", "0" * 64, "--out", str(tmp_path)])


def test_cli_fetch_model_then_tier_auto_enables(tmp_path, served, monkeypatch):
    # Real end-to-end: fetch a loadable tiny model, then a plain Redactor uses it.
    pytest.importorskip("onnx")
    pytest.importorskip("onnxruntime")
    import io

    # build a genuine tiny model archive
    import sys

    from safestream_redactor.cli import main

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_onnx_ner_inference import _build_tiny_model

    srcdir = tmp_path / "src"
    srcdir.mkdir()
    _build_tiny_model(str(srcdir / "model.int8.onnx"))
    files = {
        "model.int8.onnx": (srcdir / "model.int8.onnx").read_bytes(),
        "vocab.json": json.dumps(_VOCAB).encode(),
        "labels.json": json.dumps({str(k): v for k, v in _ID2LABEL.items()}).encode(),
    }
    archive = tmp_path / "m.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for arc, data in files.items():
            info = tarfile.TarInfo(arc)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (tmp_path / "serve").mkdir()
    archive.rename(tmp_path / "serve" / "m.tar.gz")

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(tmp_path / "serve")
    )
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        home = tmp_path / "home"
        monkeypatch.setenv("SAFESTREAM_ONNX_HOME", str(home))
        rc = main(
            [
                "fetch-model",
                "--url",
                f"http://127.0.0.1:{port}/m.tar.gz",
                "--sha256",
                sha,
                "--out",
                str(home),
            ]
        )
        assert rc == 0
    finally:
        httpd.shutdown()

    from safestream_redactor import Redactor

    r = Redactor(min_confidence=0.0)
    assert "onnx" in r.detector_names
    assert r.redact("John Smith works at Acme Corp in Paris") == (
        "[REDACTED] works at [REDACTED] in [REDACTED]"
    )
