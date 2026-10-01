"""Encoding-safety tests: undecodable bytes are surfaced, not silently dropped."""

from safestream_redactor import Redactor
from safestream_redactor.cli import main


def test_stats_count_decode_replacements(tmp_path):
    src, dst = tmp_path / "in.bin", tmp_path / "out.txt"
    # valid text around two undecodable UTF-8 bytes
    src.write_bytes(b"contact bob@x.io \xff\xfe end")
    stats = Redactor().redact_file(src, dst)
    assert stats.decode_replacements == 2
    assert "[REDACTED]" in dst.read_text()


def test_clean_input_reports_zero_replacements(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("contact bob@x.io")
    assert Redactor().redact_file(src, dst).decode_replacements == 0


def test_cli_warns_on_undecodable_bytes(tmp_path, capsys):
    src, dst = tmp_path / "in.bin", tmp_path / "out.txt"
    src.write_bytes(b"secret \xff\xfe value ssn 123-45-6789")
    assert main(["redact", str(src), "-o", str(dst)]) == 0
    err = capsys.readouterr().err
    assert "undecodable byte" in err


def test_report_includes_decode_replacements(tmp_path):
    import json

    src, dst = tmp_path / "in.bin", tmp_path / "out.txt"
    report = tmp_path / "r.json"
    src.write_bytes(b"a@b.io \xff junk")
    assert main(["redact", str(src), "-o", str(dst), "--report", str(report)]) == 0
    assert json.loads(report.read_text())["decode_replacements"] == 1


def test_encoding_flag_is_honoured(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    # latin-1 text with a byte (0xe9 = é) that is invalid UTF-8 on its own
    src.write_bytes("café bob@x.io".encode("latin-1"))
    # --no-ner: spaCy redacts the bare word "café", which this test needs intact
    assert main(["redact", str(src), "-o", str(dst), "--encoding", "latin-1", "--no-ner"]) == 0
    out = dst.read_text(encoding="latin-1")
    assert out == "café [REDACTED]"
    assert "�" not in out
