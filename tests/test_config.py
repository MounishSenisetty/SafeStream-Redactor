"""TOML policy file tests."""

import pytest

from safestream_redactor.cli import main
from safestream_redactor.config import redactor_from_config
from safestream_redactor.entities import EntityType
from safestream_redactor.policy import RedactionMode

CONFIG = """
[detection]
types = ["email", "ssn"]
min_confidence = 0.4

[redaction]
mode = "replace"
replacement = "<GONE>"

[redaction.replacements]
ssn = "<SSN>"

[custom]
words = ["ProjectX"]

[streaming]
chunk_size = 1024
overlap = 128
"""


@pytest.fixture
def config_file(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(CONFIG)
    return p


def test_redactor_from_config(config_file):
    r = redactor_from_config(config_file)
    assert r.policy.replacement == "<GONE>"
    assert r.policy.mode is RedactionMode.REPLACE
    assert r.policy.replacements == {EntityType.SSN: "<SSN>"}
    assert r.min_confidence == 0.4
    assert r.chunk_size == 1024
    assert r.overlap == 128

    out = r.redact("bob@x.io ssn: 123-45-6789 ip 10.0.0.1 ProjectX")
    assert out == "<GONE> ssn: <SSN> ip 10.0.0.1 <GONE>"


def test_cli_uses_config_and_flags_override(config_file, tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("bob@x.io and 123-45-6789")
    assert main(["redact", str(src), "-o", "-", "--config", str(config_file)]) == 0
    assert capsys.readouterr().out == "<GONE> and <SSN>"
    # --replace overrides the config default replacement
    assert (
        main(["redact", str(src), "-o", "-", "--config", str(config_file), "--replace", "#"]) == 0
    )
    assert capsys.readouterr().out == "# and <SSN>"


def test_hmac_key_from_config(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('[redaction]\nmode = "pseudonymize"\nhmac_key = "k"\n')
    r = redactor_from_config(p)
    out = r.redact("bob@x.io")
    assert out.startswith("<EMAIL_")
