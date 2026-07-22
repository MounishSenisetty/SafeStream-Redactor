"""Parallel multi-file scheduler tests."""

from pathlib import Path

from safestream_redactor import Redactor
from safestream_redactor.scheduler import ram_aware_workers, redact_tree


def _tree(root: Path) -> Path:
    src = root / "in"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("email a@b.io", encoding="utf-8")
    (src / "sub" / "b.txt").write_text("ssn: 123-45-6789", encoding="utf-8")
    return src


def test_redact_tree_mirrors_structure(tmp_path):
    src = _tree(tmp_path)
    dst = tmp_path / "out"
    results = redact_tree(src, dst, Redactor(), workers=2)
    assert len(results) == 2
    assert (dst / "a.txt").read_text() == "email [REDACTED]"
    assert (dst / "sub" / "b.txt").read_text() == "ssn: [REDACTED]"


def test_redact_tree_single_worker_inprocess(tmp_path):
    src = _tree(tmp_path)
    dst = tmp_path / "out"
    results = redact_tree(src, dst, Redactor(), workers=1)
    assert {Path(r.output_path).name for r in results} == {"a.txt", "b.txt"}
    assert all(r.bytes_written > 0 for r in results)


def test_redact_tree_empty_dir(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    assert redact_tree(src, tmp_path / "out", Redactor()) == []


def test_ram_aware_workers():
    r = Redactor()
    assert ram_aware_workers(r, requested=3) == 3
    assert ram_aware_workers(r, requested=0) == 1  # floored at 1
    assert ram_aware_workers(r) >= 1
