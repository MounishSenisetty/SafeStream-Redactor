"""SARIF output: valid structure, correct levels, and no secret leakage."""

from __future__ import annotations

import json

from safestream_redactor.cli import main
from safestream_redactor.entities import EntityType
from safestream_redactor.sarif import Finding, build_sarif

SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_build_sarif_structure() -> None:
    findings = [
        Finding(EntityType.AWS_KEY, 10, 30, 0.98, "deterministic"),
        Finding(EntityType.EMAIL, 40, 55, 0.95, "deterministic"),
    ]
    doc = build_sarif(findings, version="9.9.9")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "safestream-redactor"
    assert run["tool"]["driver"]["version"] == "9.9.9"
    assert len(run["results"]) == 2
    aws = run["results"][0]
    assert aws["ruleId"] == "aws_key"
    assert aws["level"] == "error"  # critical -> error
    region = aws["locations"][0]["physicalLocation"]["region"]
    assert region["charOffset"] == 10
    assert region["charLength"] == 20


def test_email_is_warning_level() -> None:
    doc = build_sarif(
        [Finding(EntityType.EMAIL, 0, 10, 0.9, "deterministic")],
        version="1",
    )
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_never_contains_secret_text() -> None:
    # The Finding type has no text field, so leakage is impossible by
    # construction; assert it explicitly as a regression guard.
    doc = build_sarif(
        [Finding(EntityType.AWS_KEY, 0, len(SECRET), 0.98, "deterministic")],
        version="1",
    )
    assert SECRET not in json.dumps(doc)


def test_rules_deduplicated() -> None:
    doc = build_sarif(
        [
            Finding(EntityType.EMAIL, 0, 5, 0.9, "deterministic"),
            Finding(EntityType.EMAIL, 10, 15, 0.9, "deterministic"),
        ],
        version="1",
    )
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len([r for r in rules if r["id"] == "email"]) == 1


def test_cli_detect_sarif(tmp_path, capsys) -> None:
    src = tmp_path / "in.env"
    src.write_text(f"aws key {SECRET}\n")
    rc = main(["detect", str(src), "--sarif"])
    out = capsys.readouterr().out
    doc = json.loads(out)  # must be a single valid JSON document
    assert doc["version"] == "2.1.0"
    assert SECRET not in out
    assert rc == 0
    assert any(r["ruleId"] == "aws_key" for r in doc["runs"][0]["results"])


def test_cli_detect_sarif_fail_on_detect(tmp_path) -> None:
    src = tmp_path / "in.env"
    src.write_text(f"aws key {SECRET}\n")
    assert main(["detect", str(src), "--sarif", "--fail-on-detect"]) == 1


def test_cli_sarif_regions_carry_line_and_column(tmp_path, capsys) -> None:
    # GitHub code scanning requires region.startLine to place an alert
    src = tmp_path / "in.env"
    src.write_text(f"# header\nexport AWS={SECRET}\n")
    main(["detect", str(src), "--sarif"])
    run = json.loads(capsys.readouterr().out)["runs"][0]
    assert run["columnKind"] == "unicodeCodePoints"
    region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 2 and region["startColumn"] == 12
    assert region["endLine"] == 2 and region["endColumn"] == 12 + len(SECRET)


def test_sarif_region_omits_unknown_lines() -> None:
    doc = build_sarif([Finding(EntityType.EMAIL, 3, 8, 0.9, "deterministic")], version="1")
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"charOffset": 3, "charLength": 5}
