"""No content-free reply may carry a detected value, in any tier configuration.

Property test: names and e-mail addresses built from random letters are planted in
text, every content-free reply (MCP ``scan``, ``explain_detection``, ``detectors``,
``health``; REST ``/scan``; SARIF) is collected, and none of its strings may contain
the planted surname, case-folded. ``redact`` is excluded: it returns the redacted
text, whose residual exposure is a detection-recall question.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from safestream_redactor import Redactor, __version__
from safestream_redactor.api import dispatch
from safestream_redactor.mcp_server import MCPServer
from safestream_redactor.sarif import Finding, build_sarif

FIRST = ["Maria", "James", "Aisha", "Olga", "Rahul"]


def _strings(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return [obj] if isinstance(obj, str) else []


def _replies(server: MCPServer, text: str) -> list[Any]:
    out = []
    for name in ("scan", "explain_detection", "detectors", "health"):
        args = {} if name == "health" else {"text": text}
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        msg["params"] = {"name": name, "arguments": args}
        result = server.handle(msg)["result"]
        out.append(result["structuredContent"])
    dets = server.redactor.detect(text)
    out.append(dispatch(server.redactor, "POST", "/scan", json.dumps({"text": text}).encode())[1])
    findings = [Finding(d.entity_type, d.start, d.end, d.confidence, d.source) for d in dets]
    out.append(build_sarif(findings, version=__version__))
    return out


@pytest.fixture(scope="module", params=["pattern", "gazetteer"])
def server(request: pytest.FixtureRequest) -> MCPServer:
    kwargs = {"use_gazetteer": True} if request.param == "gazetteer" else {}
    return MCPServer(Redactor(load_plugins=False, **kwargs))


@settings(max_examples=60, deadline=None)
@given(
    first=st.sampled_from(FIRST),
    last=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=6, max_size=10),
)
def test_no_content_free_reply_contains_a_planted_name(
    server: MCPServer, first: str, last: str
) -> None:
    def text(surname: str) -> str:
        return (
            f"Patient: Dr. {first} {surname.capitalize()} was seen today. "
            f"Contact {first.lower()}.{surname}@example.org or 555-0100."
        )

    # strings every reply carries anyway (types, severities, SARIF prose): the same
    # text with a fixed surname that cannot contain the generated one
    vocabulary = " ".join(_strings(_replies(server, text("qq")))).casefold()
    assume(last not in vocabulary)
    for reply in _replies(server, text(last)):
        for s in _strings(reply):
            assert last not in s.casefold(), f"planted surname reached a reply: {s[:60]!r}"
