"""Durable-output tests: atomic replacement, failure cleanup, self-overwrite guard."""

import os
import stat

import pytest

from safestream_redactor import Redactor
from safestream_redactor.entities import Detection


class _BoomDetector:
    """Fails mid-stream to simulate a crash during redaction."""

    name = "boom"

    def detect(self, text: str) -> list[Detection]:
        raise RuntimeError("simulated crash")


def test_redacting_file_onto_itself_is_rejected(tmp_path):
    p = tmp_path / "data.txt"
    p.write_text("email bob@x.io")
    with pytest.raises(ValueError, match="same file"):
        Redactor().redact_file(p, p)
    # the source must be untouched
    assert p.read_text() == "email bob@x.io"


def test_failure_leaves_no_partial_output_or_temp_files(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("email bob@x.io\n" * 10)
    r = Redactor(extra_detectors=[_BoomDetector()])
    with pytest.raises(RuntimeError, match="simulated crash"):
        r.redact_file(src, dst)
    assert not dst.exists()
    assert [p.name for p in tmp_path.iterdir()] == ["in.txt"]


def test_failure_preserves_previous_output(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("email bob@x.io")
    dst.write_text("previous good content")
    r = Redactor(extra_detectors=[_BoomDetector()])
    with pytest.raises(RuntimeError):
        r.redact_file(src, dst)
    assert dst.read_text() == "previous good content"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_overwrite_preserves_existing_permissions(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("email bob@x.io")
    dst.write_text("old")
    os.chmod(dst, 0o640)
    Redactor().redact_file(src, dst)
    assert dst.read_text() == "email [REDACTED]"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_new_output_is_not_locked_to_0600(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("email bob@x.io")
    Redactor().redact_file(src, dst)
    umask = os.umask(0)
    os.umask(umask)
    assert stat.S_IMODE(dst.stat().st_mode) == 0o666 & ~umask


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_stdin_to_file_output_matches_file_path_permissions(tmp_path, monkeypatch):
    # the stdin -> file path used its own atomic writer that left 0o600 files
    import io

    from safestream_redactor.cli import main

    dst = tmp_path / "out.txt"
    dst.write_text("old")
    os.chmod(dst, 0o644)
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"mail bob@x.io\n")))
    assert main(["redact", "-", "-o", str(dst)]) == 0
    assert dst.read_text() == "mail [REDACTED]\n"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o644


def test_report_write_is_atomic(tmp_path, monkeypatch):
    from safestream_redactor import report

    path = tmp_path / "report.json"
    path.write_text('{"previous": true}\n')

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(report.json, "dump", _boom)
    with pytest.raises(OSError, match="disk full"):
        report.write_report(str(path), {"total_detections": 1})
    assert path.read_text() == '{"previous": true}\n'
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]
