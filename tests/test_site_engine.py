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
    bad = json.loads(engine.analyze("x", json.dumps({"custom_patterns": "("})))
    assert not bad["ok"] and bad["error"]  # a user-facing message for an invalid regex
