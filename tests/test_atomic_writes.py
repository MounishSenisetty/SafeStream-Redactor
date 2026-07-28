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
