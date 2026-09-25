"""Run-report tests: counts are right and reports never contain matched text."""

import json

from safestream_redactor import Redactor
from safestream_redactor.cli import main
from safestream_redactor.report import RedactionStats, build_report

SAMPLE = "email bob@x.io and again alice@y.co ssn: 123-45-6789\n"


def test_redact_file_returns_stats(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_bytes((SAMPLE * 3).encode())  # exact bytes, same on every OS
    stats = Redactor().redact_file(src, dst)
    assert stats.counts == {"email": 6, "ssn": 3}
    assert stats.total == 9
    assert stats.chars_in == len(SAMPLE) * 3
    assert stats.chars_out == len(dst.read_text())


def test_redact_stream_accumulates_stats():
    stats = RedactionStats()
    out = "".join(Redactor().redact_stream([SAMPLE], stats))
    assert stats.counts == {"email": 2, "ssn": 1}
    assert stats.chars_out == len(out)


def test_stats_merge():
    a, b = RedactionStats(), RedactionStats()
    "".join(Redactor().redact_stream([SAMPLE], a))
    "".join(Redactor().redact_stream([SAMPLE], b))
    a.merge(b)
    assert a.counts == {"email": 4, "ssn": 2}
    assert a.chars_in == 2 * len(SAMPLE)


def test_report_schema_is_content_free(tmp_path):
    src, out, report = tmp_path / "in.txt", tmp_path / "out.txt", tmp_path / "report.json"
    src.write_text(SAMPLE)
    assert main(["redact", str(src), "-o", str(out), "--report", str(report)]) == 0
    data = json.loads(report.read_text())
    assert data["tool"] == "safestream-redactor"
    assert data["files"] == 1
    assert data["total_detections"] == 3
    assert data["detections_by_type"] == {"email": 2, "ssn": 1}
    # the report must never leak what was redacted
    raw = report.read_text()
    for secret in ("bob@x.io", "alice@y.co", "123-45-6789"):
        assert secret not in raw


def test_stats_flag_prints_summary(tmp_path, capsys):
    src, out = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text(SAMPLE)
    assert main(["redact", str(src), "-o", str(out), "--stats"]) == 0
    err = capsys.readouterr().err
    assert "3 detection(s)" in err and "email=2" in err and "ssn=1" in err


def test_directory_report_aggregates(tmp_path):
    src = tmp_path / "in"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("email a@b.io")
    (src / "sub" / "b.txt").write_text("ssn: 123-45-6789")
    report = tmp_path / "report.json"
    assert (
        main(
            [
                "redact",
                str(src),
                "-o",
                str(tmp_path / "out"),
                "--workers",
                "1",
                "--report",
                str(report),
            ]
        )
        == 0
    )
    data = json.loads(report.read_text())
    assert data["files"] == 2
    assert data["detections_by_type"] == {"email": 1, "ssn": 1}
    assert data["chars_in"] > 0 and data["chars_out"] > 0


def test_build_report_shape():
    stats = RedactionStats()
    report = build_report(stats, files=0, duration_seconds=0.1234, version="9.9.9")
    assert report["version"] == "9.9.9"
    assert report["total_detections"] == 0
    assert report["duration_seconds"] == 0.123
