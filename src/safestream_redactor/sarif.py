"""SARIF 2.1.0 output for the CI secret gate.

SARIF is the format GitHub code scanning, and most CI security dashboards,
ingest. Emitting it lets ``safestream detect --sarif`` upload findings as
annotations on a pull request. Like every other report in this project the
schema is **content-free**: it carries the entity type, location, severity, and
confidence of each finding, never the matched secret — a SARIF file is an
artifact that gets uploaded and stored, so putting the secret in it would leak
it exactly where it is most visible.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from safestream_redactor.entities import EntityType
from safestream_redactor.severity import CRITICAL, HIGH, LOW, MEDIUM, severity_for

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/MounishSenisetty/SafeStream-Redactor"

# SARIF result levels map from our four-level severity.
_LEVEL = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note"}
# SARIF security-severity is a 0-10 string GitHub uses to sort code-scanning
# alerts; map our levels onto CVSS-like bands.
_SECURITY_SCORE = {CRITICAL: "9.5", HIGH: "8.0", MEDIUM: "5.0", LOW: "3.0"}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single content-free finding for the SARIF report."""

    entity_type: EntityType
    start: int
    end: int
    confidence: float
    detector: str
    uri: str = "input"
    # 1-based position of ``start`` / ``end`` (``end`` exclusive, as SARIF's
    # endColumn is). GitHub code scanning requires ``region.startLine`` to place
    # an alert on a file, so the CLI always fills these in; they stay optional
    # for callers that only have character offsets.
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


def _region(f: Finding) -> dict[str, int]:
    region = {"charOffset": f.start, "charLength": f.end - f.start}
    for key, value in (
        ("startLine", f.line),
        ("startColumn", f.column),
        ("endLine", f.end_line),
        ("endColumn", f.end_column),
    ):
        if value is not None:
            region[key] = value
    return region


def _rules(types: Iterable[EntityType]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for entity_type in sorted(set(types), key=lambda t: t.value):
        sev = severity_for(entity_type)
        rules.append(
            {
                "id": entity_type.value,
                "name": entity_type.value,
                "shortDescription": {"text": f"{entity_type.value} detected"},
                "defaultConfiguration": {"level": _LEVEL[sev]},
                "properties": {
                    "security-severity": _SECURITY_SCORE[sev],
                    "tags": ["security", "secret" if sev in (CRITICAL, HIGH) else "pii"],
                },
            }
        )
    return rules


def build_sarif(findings: Iterable[Finding], *, version: str) -> dict[str, object]:
    """Assemble a SARIF 2.1.0 log from findings. Never includes matched text.

    Each finding carries its own artifact ``uri``, so a single report can span
    many scanned files (as the CLI does over a set of staged files).
    """
    findings = list(findings)
    results = []
    for f in findings:
        sev = severity_for(f.entity_type)
        results.append(
            {
                "ruleId": f.entity_type.value,
                "level": _LEVEL[sev],
                "message": {
                    "text": (
                        f"{f.entity_type.value} ({sev}) detected by the {f.detector} tier "
                        f"at characters {f.start}-{f.end} (confidence {f.confidence:.2f}). "
                        "The matched value is intentionally omitted."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.uri},
                            "region": _region(f),
                        }
                    }
                ],
                "properties": {
                    "confidence": round(f.confidence, 3),
                    "security-severity": _SECURITY_SCORE[sev],
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "safestream-redactor",
                        "version": version,
                        "informationUri": INFORMATION_URI,
                        "rules": _rules(f.entity_type for f in findings),
                    }
                },
                "results": results,
                # Python string offsets count code points; SARIF's default column
                # unit is UTF-16 code units, which differs on astral characters.
                "columnKind": "unicodeCodePoints",
            }
        ],
    }
