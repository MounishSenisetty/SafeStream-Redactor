"""CLI tests, calling main() in-process for speed."""

import json

import pytest

from safestream_redactor.cli import main

SAMPLE = "email bob@x.io ssn: 123-45-6789 codename ProjectX\n"


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "in.txt"
    p.write_bytes(SAMPLE.encode())  # exact bytes: line endings pass through verbatim
    return p


def run(capsys, *argv) -> str:
    assert main([str(a) for a in argv]) == 0
    return capsys.readouterr().out


def test_redact_to_file(sample, tmp_path):
    out = tmp_path / "out.txt"
    assert main(["redact", str(sample), "-o", str(out)]) == 0
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_redact_stdout_with_replace(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--replace", "***")
    assert out == "email *** ssn: *** codename ProjectX\n"


def test_types_filter(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--types", "email")
    assert out == "email [REDACTED] ssn: 123-45-6789 codename ProjectX\n"


def test_custom_word(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--custom-word", "ProjectX")
    assert "ProjectX" not in out


def test_mask_mode(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--mode", "mask", "--keep-last", "4")
    assert "*******6789" in out


def test_pseudonymize_requires_key(sample, tmp_path):
    with pytest.raises(SystemExit):
        main(["redact", str(sample), "-o", str(tmp_path / "o"), "--mode", "pseudonymize"])


def test_per_type_replacement(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--replace-type", "email=<EMAIL>")
    assert "<EMAIL>" in out and "ssn: [REDACTED]" in out


def test_detect_json(sample, capsys):
    out = run(capsys, "detect", sample, "--json")
    records = [json.loads(line) for line in out.splitlines()]
    assert {r["type"] for r in records} == {"email", "ssn"}
    assert all({"start", "end", "text", "confidence"} <= r.keys() for r in records)


def test_fail_on_detect_gates_ci(sample, tmp_path, capsys):
    # findings -> exit 1; clean input -> exit 0
    assert main(["detect", str(sample), "--fail-on-detect"]) == 1
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing sensitive here\n")
    assert main(["detect", str(clean), "--fail-on-detect"]) == 0
    capsys.readouterr()


def test_stdin_stdout(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ip 10.0.0.1 here"))
    out = run(capsys, "redact", "-", "-o", "-")
    assert out == "ip [REDACTED] here"


def test_stdin_to_file(capsys, monkeypatch, tmp_path):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ip 10.0.0.1 here"))
    out = tmp_path / "out.txt"
    assert main(["redact", "-", "-o", str(out)]) == 0
    assert out.read_text() == "ip [REDACTED] here"


def test_missing_input_file_errors(capsys, tmp_path):
    assert main(["redact", str(tmp_path / "nope.txt"), "-o", "-"]) == 1
    assert "error" in capsys.readouterr().err


def test_memory_limit_generous_admits(sample, tmp_path, capsys):
    out = tmp_path / "out.txt"
    assert main(["redact", str(sample), "-o", str(out), "--memory-limit", "256MB"]) == 0
    assert "memory budget" in capsys.readouterr().err
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_memory_limit_fail_closed_exit_3(sample, capsys):
    # A 1 MB budget cannot hold even one worker's working set: fail closed.
    assert main(["detect", str(sample), "--memory-limit", "1MB"]) == 3
    assert "resource-exhaustion" in capsys.readouterr().err


def test_memory_limit_caps_workers(sample, tmp_path, capsys):
    out = tmp_path / "out.txt"
    # Ask for many workers under a tight budget; the run still succeeds because
    # the budget silently caps concurrency rather than exceeding the limit.
    assert (
        main(["redact", str(sample), "-o", str(out), "--memory-limit", "48MB", "--workers", "16"])
        == 0
    )
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_memory_limit_bad_value_errors(sample, capsys):
    assert main(["detect", str(sample), "--memory-limit", "notasize"]) == 1
    assert "error" in capsys.readouterr().err


def test_no_entropy_flag_disables_both_entropy_tiers_with_config(tmp_path):
    # Regression (F3): via the --config overlay path, --no-entropy must remove
    # BOTH the base entropy tier and the compound-secret tier, matching the
    # constructor's use_entropy gating.
    from safestream_redactor.cli import _build_parser, _build_redactor

    cfg = tmp_path / "policy.toml"
    cfg.write_text("[detection]\nuse_entropy = true\n", encoding="utf-8")
    args = _build_parser().parse_args(
        ["redact", "in.txt", "-o", "out.txt", "--config", str(cfg), "--no-entropy"]
    )
    redactor = _build_redactor(args)
    assert "entropy" not in redactor.detector_names
    assert "compound_secret" not in redactor.detector_names


def test_constructor_use_entropy_false_disables_both_tiers():
    from safestream_redactor.redactor import Redactor

    names = Redactor(use_entropy=False).detector_names
    assert "entropy" not in names
    assert "compound_secret" not in names
    # sanity: they are present when entropy is enabled (the default)
    on = Redactor(use_entropy=True).detector_names
    assert "entropy" in on and "compound_secret" in on
