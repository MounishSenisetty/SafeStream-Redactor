"""site/engine.py: the demo's glue, run here under CPython (in the browser, Pyodide)."""

from __future__ import annotations

import importlib.util
import json
from itertools import pairwise
from pathlib import Path

_path = Path(__file__).resolve().parent.parent / "site" / "engine.py"
_spec = importlib.util.spec_from_file_location("demo_engine", _path)
assert _spec and _spec.loader
engine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(engine)

SETTINGS = json.dumps({})


def _result(raw: str) -> dict:
    data = json.loads(raw)
    assert data["ok"], data
    return data["result"]


def test_offsets_are_utf16_after_astral_characters() -> None:
    # JavaScript slices strings in UTF-16 units: an emoji is two of them
    text = "😀😀 mail bob@corp.io"
    (f,) = _result(engine.analyze(text, SETTINGS))["findings"]
    js_units = text.encode("utf-16-le")
    assert js_units[f["start"] * 2 : f["end"] * 2].decode("utf-16-le") == "bob@corp.io"


def test_analyze_matches_the_library() -> None:
    from safestream_redactor import Redactor

    text = "user=bob@corp.example ssn: 123-45-6789 key=AKIAIOSFODNN7EXAMPLE\n"
    assert _result(engine.analyze(text, SETTINGS))["redacted"] == Redactor().redact(text)


def test_trace_passes_cover_the_input() -> None:
    text = ("2026 INFO user=maria@corpmail.com ip=10.1.2.3\n") * 1500
    out = _result(engine.trace(text, SETTINGS, 8192))
    passes = out["passes"]
    assert len(passes) > 1
    assert passes[0]["emit"][0] == 0 and passes[-1]["emit"][1] == len(text)
    assert all(a["emit"][1] == b["emit"][0] for a, b in pairwise(passes))


def test_rest_and_mcp_never_return_the_secret() -> None:
    body = json.dumps({"text": "key AKIAIOSFODNN7EXAMPLE"})
    rest = _result(engine.rest("POST", "/scan", body, SETTINGS))
    assert rest["status"] == 200 and "AKIA" not in json.dumps(rest)
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "scan", "arguments": {"text": "key AKIAIOSFODNN7EXAMPLE"}},
    }
    reply = _result(engine.mcp(json.dumps(call), SETTINGS))
    assert reply["result"]["structuredContent"]["count"] == 1 and "AKIA" not in json.dumps(reply)


def test_bad_input_is_reported_not_raised() -> None:
    assert _result(engine.mcp("{not json", SETTINGS))["error"]["code"] == -32700
    bad = json.loads(engine.analyze("x", json.dumps({"custom": {"patterns": ["("]}})))
    assert not bad["ok"] and bad["error"]  # a user-facing message for an invalid regex


# --- settings are a policy file -------------------------------------------------


def _policy(**redaction: object) -> str:
    return json.dumps({"redaction": redaction})


def test_every_redaction_mode_the_page_offers_runs() -> None:
    from safestream_redactor import RedactionPolicy, Redactor

    text = "mail bob@corp.io ssn 123-45-6789\n"
    key = "k" * 16
    for mode, extra in (
        ("replace", {"replacement": "<X>"}),
        ("mask", {"mask_keep_last": 2, "mask_char": "#"}),
        ("pseudonymize", {"hmac_key": key}),
        ("hash", {"hash_salt": "salt", "hash_algorithm": "sha512"}),
        ("fictionalize", {"hmac_key": key}),
    ):
        out = _result(engine.analyze(text, _policy(mode=mode, **extra)))["redacted"]
        expected = Redactor(policy=RedactionPolicy(mode=mode, **extra)).redact(text)  # type: ignore[arg-type]
        assert out == expected and "bob@corp.io" not in out, mode


def test_per_type_replacements_and_opt_in_tiers() -> None:
    settings = json.dumps(
        {
            "detection": {"use_regional": True, "types": ["email", "iban"]},
            "redaction": {"replacements": {"email": "<EMAIL>"}},
        }
    )
    out = _result(engine.analyze("bob@corp.io GB82 WEST 1234 5698 7654 32 123-45-6789", settings))
    assert out["redacted"].startswith("<EMAIL> [REDACTED] 123-45-6789")
    assert [f["type"] for f in out["findings"]] == ["email", "iban"]


def test_policy_errors_come_from_the_config_loader() -> None:
    typo = json.loads(engine.analyze("x", _policy(replacment="x")))
    assert not typo["ok"] and "did you mean 'replacement'" in typo["error"]
    keyless = json.loads(engine.analyze("x", _policy(mode="pseudonymize")))
    assert not keyless["ok"] and "hmac_key" in keyless["error"]


def test_check_policy_round_trips_toml() -> None:
    toml = (
        '[detection]\nmin_confidence = 0.7\n\n[redaction]\nmode = "mask"\n\n'
        '[custom]\nwords = ["Falcon"]\n'
    )
    assert _result(engine.check_policy(toml)) == {
        "detection": {"min_confidence": 0.7},
        "redaction": {"mode": "mask"},
        "custom": {"words": ["Falcon"]},
    }
    bad = json.loads(engine.check_policy("[redaction\n"))
    assert not bad["ok"] and bad["error"].startswith("Invalid TOML")
    assert _result(engine.check_policy(_result(engine.info())["starter_config"]))


def test_determinism_runs_agree() -> None:
    text = "user=bob@corp.io key=AKIAIOSFODNN7EXAMPLE\n" * 600
    out = _result(engine.determinism(text, SETTINGS))
    assert out["identical"] and len(out["runs"]) == 4
    assert len({r["sha256"] for r in out["runs"]}) == 1


def test_bench_streams_generated_input() -> None:
    seen: list[tuple[int, int, str]] = []
    out = _result(engine.bench(SETTINGS, "[50000, 200000]", lambda *a: seen.append(a)))
    small, large = out["rows"]
    assert small["bytes"] == 50000 and large["bytes"] == 200000
    assert large["out_bytes"] < 200000  # long secrets became [REDACTED]
    assert all(r["peak_bytes"] > 0 and r["mb_per_s"] for r in out["rows"])
    assert len(seen) == 4
    assert not json.loads(engine.bench(SETTINGS, "[0]"))["ok"]


def test_run_cli_is_the_real_command_line() -> None:
    from safestream_redactor import netguard

    try:
        files = json.dumps({"change.diff": "+aws_key=AKIAIOSFODNN7EXAMPLE\n"})
        hit = _result(engine.run_cli('["detect", "change.diff", "--fail-on-detect"]', files))
        assert hit["exit"] == 1 and "change.diff:1:10: aws_key" in hit["stdout"]
        assert "AKIA" not in hit["stdout"] + hit["stderr"]
        clean = json.dumps({"ok.txt": "nothing to see\n"})
        assert (
            _result(engine.run_cli('["detect", "ok.txt", "--fail-on-detect"]', clean))["exit"] == 0
        )
        red = _result(
            engine.run_cli('["redact", "a.txt", "-o", "b.txt"]', '{"a.txt": "bob@corp.io\\n"}')
        )
        assert red["files"] == {"b.txt": "[REDACTED]\n"}
        assert _result(engine.run_cli('["detect"]', "{}"))["exit"] == 2  # argparse usage error
        assert not json.loads(engine.run_cli('["serve"]', "{}"))["ok"]
        assert not json.loads(engine.run_cli('["detect", "x"]', '{"../x": "a"}'))["ok"]
    finally:
        netguard.uninstall()
