"""CLI tests, calling main() in-process for speed."""

import json

import pytest

from safestream_redactor.cli import main

SAMPLE = "email bob@x.io ssn: 123-45-6789 codename ProjectX\n"


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "in.txt"
    p.write_text(SAMPLE)
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


def test_stdin_stdout(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ip 10.0.0.1 here"))
    out = run(capsys, "redact", "-", "-o", "-")
    assert out == "ip [REDACTED] here"


def test_missing_input_file_errors(capsys, tmp_path):
    assert main(["redact", str(tmp_path / "nope.txt"), "-o", "-"]) == 1
    assert "error" in capsys.readouterr().err
