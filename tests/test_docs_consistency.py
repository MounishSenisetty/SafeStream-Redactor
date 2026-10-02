"""Docs and shipped examples must agree with the code's default overlap (R-DOC-1)."""

from __future__ import annotations

import re
from pathlib import Path

from safestream_redactor import Redactor
from safestream_redactor.config import load_config, redactor_kwargs_from_config
from safestream_redactor.engine import DEFAULT_OVERLAP

ROOT = Path(__file__).resolve().parent.parent
# AUDIT_FINDINGS.md quotes the *old* wording on purpose; CHANGELOG records the 4096 -> 8192 change.
CURRENT_DOCS = [
    "README.md",
    "SYSTEM_DESIGN.md",
    "src/README_PYPI.md",
    *sorted(
        str(p.relative_to(ROOT))
        for p in (ROOT / "docs").glob("*.md")
        if p.name != "AUDIT_FINDINGS.md"
    ),
    "paper/ftnct09/safestream-redactor-ftnct09.tex",
]
STALE = re.compile(
    r"overlap[^\n|]{0,60}\b(?:4 ?KiB|4 ?KB|4096)\b|DEFAULT_OVERLAP\W+4096", re.IGNORECASE
)


def test_default_overlap_is_8_kib() -> None:
    assert DEFAULT_OVERLAP == 8192  # the number every doc below quotes


def test_no_current_doc_states_a_stale_default_overlap() -> None:
    stale = []
    for rel in CURRENT_DOCS:
        for n, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            # a deliberately small overlap used by a test is not a claim about the default
            if (
                STALE.search(line)
                and "deliberately small" not in line
                and "default" in line.lower()
            ):
                stale.append(f"{rel}:{n}: {line.strip()[:100]}")
    assert not stale, "docs state a non-8 KiB default overlap:\n" + "\n".join(stale)


def test_example_policy_builds_under_the_fail_closed_guard() -> None:
    kwargs = redactor_kwargs_from_config(load_config(ROOT / "examples" / "policy.toml"))
    kwargs.pop("use_ner", None)  # spaCy is an optional extra; the overlap is what is under test
    kwargs.pop("ner_model", None)
    assert Redactor(**kwargs).overlap >= DEFAULT_OVERLAP
