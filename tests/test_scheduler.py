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


def _many_files(root: Path, n: int) -> Path:
    src = root / "in"
    src.mkdir()
    for i in range(n):
        (src / f"f{i:02d}.txt").write_text(f"email user{i}@x.io")
    return src


def test_progress_callback_reports_every_file(tmp_path):
    src = _many_files(tmp_path, 6)
    seen = []
    redact_tree(
        src, tmp_path / "out", Redactor(), workers=1, progress=lambda d, t: seen.append((d, t))
    )
    assert [d for d, _ in seen] == [1, 2, 3, 4, 5, 6]
    assert all(t == 6 for _, t in seen)


def test_progress_and_order_preserved_parallel(tmp_path):
    src = _many_files(tmp_path, 8)
    seen = []
    results = redact_tree(
        src, tmp_path / "out", Redactor(), workers=4, progress=lambda d, t: seen.append(d)
    )
    # every file reported once, ending at the total, regardless of finish order
    assert sorted(seen) == [1, 2, 3, 4, 5, 6, 7, 8]
    # results stay in sorted input-path order even though completion order varies
    names = [Path(r.input_path).name for r in results]
    assert names == sorted(names)


def test_inprocess_run_does_not_leak_netguard(tmp_path):
    # the single-worker fallback runs in the caller's process; the offline
    # guard it installs must be removed again when the run finishes, or a
    # library call would permanently patch the host application's sockets.
    # The invariant is that the run leaves global guard state unchanged,
    # whatever it was on entry (other tests may have installed it).
    from safestream_redactor import netguard

    netguard.uninstall()
    try:
        assert not netguard.is_installed()
        src = _tree(tmp_path)
        redact_tree(src, tmp_path / "out", Redactor(), workers=1)
        assert not netguard.is_installed()
    finally:
        netguard.uninstall()


def test_inprocess_run_keeps_preinstalled_netguard(tmp_path):
    # ...but when the caller (e.g. the CLI) installed the guard itself, the
    # run must not tear down that outer guard on exit
    from safestream_redactor import netguard

    netguard.install()
    try:
        src = _tree(tmp_path)
        redact_tree(src, tmp_path / "out", Redactor(), workers=1)
        assert netguard.is_installed()
    finally:
        netguard.uninstall()


def test_ram_aware_workers():
    r = Redactor()
    assert ram_aware_workers(r, requested=3) == 3
    assert ram_aware_workers(r, requested=0) == 1  # floored at 1
    assert ram_aware_workers(r) >= 1
