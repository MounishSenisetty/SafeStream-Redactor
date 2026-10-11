"""TOML policy file tests."""

import json

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
allow_unsafe_overlap = true  # tiny overlap here exercises config plumbing, not safety
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


def test_profile_from_cli_and_policy_file(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("Signed Aug 19, 2024")
    assert main(["redact", str(src), "-o", "-"]) == 0
    assert capsys.readouterr().out == "Signed Aug 19, 2024"
    assert main(["redact", str(src), "-o", "-", "--profile", "prose"]) == 0
    assert capsys.readouterr().out == "Signed [REDACTED]"
    policy = tmp_path / "p.toml"
    policy.write_text('[detection]\nprofile = "prose"\n')
    assert redactor_from_config(policy).profile == "prose"
    policy.write_text('[detection]\nprofile = "poetry"\n')
    with pytest.raises(ValueError, match="unknown profile"):
        redactor_from_config(policy)


def test_cli_detection_flags_override_config(config_file, tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("bob@x.io and 123-45-6789 codename ProjectY chunk sk-ant-" + "Ab12Cd34" * 5)
    assert (
        main(
            [
                "redact",
                str(src),
                "-o",
                "-",
                "--config",
                str(config_file),
                "--types",
                "email,anthropic_key",
                "--min-confidence",
                "0.6",
                "--no-entropy",
                "--custom-word",
                "ProjectY",
                "--chunk-size",
                "2048",
                "--overlap",
                "256",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    # email redacted, custom word from the flag redacted, ssn no longer in scope
    assert "bob@x.io" not in out and "ProjectY" not in out
    assert "123-45-6789" in out
    assert "sk-ant-" not in out


def test_hmac_key_from_config(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('[redaction]\nmode = "pseudonymize"\nhmac_key = "k"\n')
    r = redactor_from_config(p)
    out = r.redact("bob@x.io")
    assert out.startswith("<EMAIL_")


def test_calibration_model_loaded_from_config(tmp_path):
    from safestream_redactor import Calibrator
    from safestream_redactor.calibration import FEATURE_NAMES

    # a bias-only model forcing every detection to ~0 probability, referenced by
    # a path relative to the config file
    Calibrator([-50.0] + [0.0] * len(FEATURE_NAMES)).save(tmp_path / "model.json")
    p = tmp_path / "p.toml"
    p.write_text('[calibration]\nmodel = "model.json"\n')
    r = redactor_from_config(p)
    assert r.calibrator is not None
    # calibrated to ~0, so nothing clears the default threshold
    assert r.redact("bob@x.io ssn 123-45-6789") == "bob@x.io ssn 123-45-6789"


def test_unknown_key_fails_closed(tmp_path):
    # a misspelled key must error, not silently fall back to the default and
    # ship unredacted output
    p = tmp_path / "p.toml"
    p.write_text('[redaction]\nreplacment = "<X>"\n')
    with pytest.raises(ValueError, match=r"unknown key 'replacment'.*did you mean 'replacement'"):
        redactor_from_config(p)


def test_unknown_section_fails_closed(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('[redation]\nmode = "mask"\n')
    with pytest.raises(ValueError, match="unknown config section"):
        redactor_from_config(p)


def test_replacements_entity_keys_are_not_rejected(tmp_path):
    # keys under redaction.replacements are entity names, not config keys
    p = tmp_path / "p.toml"
    p.write_text('[redaction.replacements]\nemail = "<E>"\nssn = "<S>"\n')
    r = redactor_from_config(p)
    assert r.redact("bob@x.io ssn: 123-45-6789") == "<E> ssn: <S>"


def test_init_config_emits_a_usable_policy(tmp_path):
    # the generated starter must load without error and actually redact,
    # closing the loop between init-config and the strict validator
    policy = tmp_path / "policy.toml"
    assert main(["init-config", "-o", str(policy)]) == 0
    src = tmp_path / "in.txt"
    src.write_text("mail bob@x.io ssn 123-45-6789")
    out = tmp_path / "out.txt"
    assert main(["redact", str(src), "-o", str(out), "--config", str(policy)]) == 0
    assert out.read_text() == "mail [REDACTED] ssn [REDACTED]"


def test_init_config_refuses_to_clobber(tmp_path):
    policy = tmp_path / "policy.toml"
    policy.write_text("keep me")
    with pytest.raises(SystemExit, match="already exists"):
        main(["init-config", "-o", str(policy)])
    assert policy.read_text() == "keep me"
    assert main(["init-config", "-o", str(policy), "--force"]) == 0
    assert policy.read_text() != "keep me"


# --------------------------------------------------------------------------
# value types are validated, not just key names (fail closed)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "match"),
    [
        # a non-empty string is truthy: this used to leave the tier switched ON
        ('[detection]\nuse_entropy = "no"\n', r"use_entropy must be a boolean, got str"),
        # used to crash mid-stream with a TypeError after partial stdout output
        ('[detection]\nmin_confidence = "0.5"\n', r"min_confidence must be a number"),
        ("[detection]\nmin_confidence = true\n", r"min_confidence must be a number"),
        ('[detection]\ntypes = "email"\n', r"types must be an array of strings"),
        ("[detection]\ntypes = [1, 2]\n", r"types must be an array of strings"),
        ("[streaming]\nchunk_size = 1.5\n", r"chunk_size must be an integer"),
        ("[streaming]\nchunk_size = true\n", r"chunk_size must be an integer"),
        ("[redaction]\nhmac_key = 42\n", r"hmac_key must be a string"),
        ("[redaction.replacements]\nemail = 1\n", r"replacements must be a table of strings"),
        ('[custom]\nwords = "ProjectX"\n', r"words must be an array of strings"),
    ],
)
def test_ill_typed_values_fail_closed(tmp_path, body, match):
    p = tmp_path / "p.toml"
    p.write_text(body)
    with pytest.raises(ValueError, match=match):
        redactor_from_config(p)


def test_zero_chunk_size_in_config_is_rejected(tmp_path):
    # chunk_size = 0 used to write an empty output file (all input dropped)
    p = tmp_path / "p.toml"
    p.write_text("[streaming]\nchunk_size = 0\n")
    with pytest.raises(ValueError, match="chunk_size must be a positive integer"):
        redactor_from_config(p)


def test_toml_syntax_error_is_a_value_error(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text("[detection\n")
    with pytest.raises(ValueError, match="invalid TOML"):
        redactor_from_config(p)


def test_cli_reports_bad_config_without_traceback(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("bob@x.io")
    p = tmp_path / "p.toml"
    p.write_text('[detection]\nmin_confidence = "0.5"\n')
    assert main(["redact", str(src), "-o", "-", "--config", str(p)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""  # nothing half-written before the failure
    assert "min_confidence must be a number" in captured.err


def test_tiers_reachable_from_config(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text(
        "[detection]\nuse_gazetteer = true\nuse_ensemble = true\n"
        'semantic_policy = "high_recall"\nbackend = "python"\n'
    )
    names = redactor_from_config(p).detector_names
    assert {"gazetteer_name", "semantic_ensemble"} <= set(names)


def test_cli_types_flag_applies_to_every_tier_with_config(tmp_path, capsys):
    # --types used to rebuild only the regex tier when --config was given, so the
    # label/entropy tiers kept emitting out-of-scope types (id_number here)
    p = tmp_path / "p.toml"
    p.write_text("[detection]\nmin_confidence = 0.5\n")
    src = tmp_path / "in.txt"
    src.write_text("email bob@x.io employee id: 88213471\n")
    with_cfg = ["detect", str(src), "--types", "email", "--json", "--config", str(p)]
    assert main(with_cfg) == 0
    types_with = {json.loads(line)["type"] for line in capsys.readouterr().out.splitlines()}
    assert main(["detect", str(src), "--types", "email", "--json"]) == 0
    types_without = {json.loads(line)["type"] for line in capsys.readouterr().out.splitlines()}
    assert types_with == types_without == {"email"}


def test_cli_custom_words_add_to_config_words(config_file, tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("ProjectX and ProjectY")
    argv = ["redact", str(src), "-o", "-", "--config", str(config_file)]
    assert main([*argv, "--custom-word", "ProjectY"]) == 0
    assert capsys.readouterr().out == "<GONE> and <GONE>"
