"""MCP server: protocol handshake, tools, and the no-secret-leak guarantee."""

from __future__ import annotations

import io
import json

import pytest

from safestream_redactor import Redactor
from safestream_redactor.mcp_server import (
    INVALID_PARAMS,
    MAX_TEXT_BYTES,
    METHOD_NOT_FOUND,
    PROTOCOL_VERSION,
    MCPServer,
    serve_stdio,
)

# A payload with a real-shaped AWS key and an email; the literal secret must
# never appear in scan/explain output.
SECRET = "AKIAIOSFODNN7EXAMPLE"
SAMPLE = f"user bob@corp.example.com aws key {SECRET} done"


@pytest.fixture
def server() -> MCPServer:
    return MCPServer(Redactor())


def call(server: MCPServer, name: str, **arguments) -> dict:
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert resp is not None
    assert "error" not in resp, resp
    return resp["result"]["structuredContent"]


def test_initialize_handshake(server: MCPServer) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "safestream-redactor"


def test_notification_returns_none(server: MCPServer) -> None:
    # No `id` => notification => no response.
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_tools_list_advertises_all(server: MCPServer) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"scan", "redact", "explain_detection", "detectors", "health"} <= names
    for tool in resp["result"]["tools"]:
        assert "inputSchema" in tool and "description" in tool


def test_scan_returns_metadata(server: MCPServer) -> None:
    result = call(server, "scan", text=SAMPLE)
    assert result["count"] >= 2
    types = {f["type"] for f in result["findings"]}
    assert "aws_key" in types and "email" in types
    aws = next(f for f in result["findings"] if f["type"] == "aws_key")
    assert aws["severity"] == "critical"
    assert aws["end"] > aws["start"]


def test_scan_never_returns_the_secret(server: MCPServer) -> None:
    # The cardinal security property: metadata only, no matched substring.
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"text": SAMPLE}},
        }
    )
    blob = json.dumps(resp)
    assert SECRET not in blob
    assert "bob@corp.example.com" not in blob


def test_explain_never_returns_the_secret(server: MCPServer) -> None:
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "explain_detection", "arguments": {"text": SAMPLE}},
        }
    )
    assert SECRET not in json.dumps(resp)


def test_redact_removes_the_secret(server: MCPServer) -> None:
    result = call(server, "redact", text=SAMPLE)
    assert SECRET not in result["redacted_text"]
    assert result["total_detections"] >= 2


def test_detectors_tool_reports_requirements(server: MCPServer) -> None:
    result = call(server, "detectors")
    names = {t["name"] for t in result["tiers"]}
    assert "deterministic" in names
    assert result["min_safe_overlap"] == 8 * 1024


def test_health_tool(server: MCPServer) -> None:
    result = call(server, "health")
    assert result["status"] == "ok"
    assert result["offline"] is True


def test_unknown_method_is_error(server: MCPServer) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})
    assert resp["error"]["code"] == METHOD_NOT_FOUND


def test_unknown_tool_is_error(server: MCPServer) -> None:
    resp = server.handle(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "bogus"}}
    )
    assert resp["error"]["code"] == INVALID_PARAMS


def test_oversized_text_rejected(server: MCPServer) -> None:
    big = "a" * (MAX_TEXT_BYTES + 1)
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"text": big}},
        }
    )
    assert resp["error"]["code"] == INVALID_PARAMS


def test_missing_text_argument_rejected(server: MCPServer) -> None:
    resp = server.handle(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "scan"}}
    )
    assert resp["error"]["code"] == INVALID_PARAMS


def test_serve_stdio_roundtrip() -> None:
    requests = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "scan", "arguments": {"text": SAMPLE}},
                }
            ),
            "not json at all",
        ]
    )
    out = io.StringIO()
    serve_stdio(Redactor(), stdin=io.StringIO(requests), stdout=out)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    # initialize reply, scan reply, and a parse-error for the junk line;
    # the notification produced no output.
    assert len(lines) == 3
    assert lines[0]["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert SECRET not in out.getvalue()
    assert lines[-1]["error"]["code"] == -32700


def test_invalid_jsonrpc_request_rejected(server: MCPServer) -> None:
    resp = server.handle({"id": 9, "method": "ping"})  # missing jsonrpc field
    assert resp["error"]["code"] == -32600


def test_ping_returns_empty(server: MCPServer) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 10, "method": "ping"})
    assert resp["result"] == {}


def test_initialized_request_with_id_ok(server: MCPServer) -> None:
    resp = server.handle({"jsonrpc": "2.0", "id": 11, "method": "notifications/initialized"})
    assert resp["result"] == {}


def test_internal_error_is_mapped_not_raised() -> None:
    class Boom(Redactor):
        def detect(self, text: str):  # type: ignore[override]
            raise RuntimeError("the secret is hunter2")  # must not leak

    server = MCPServer(Boom())
    resp = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": {"text": "x"}},
        }
    )
    assert resp["error"]["code"] == -32603
    # the exception message (which could echo content) must not appear
    assert "hunter2" not in resp["error"]["message"]


def test_serve_stdio_non_object_line() -> None:
    out = io.StringIO()
    serve_stdio(Redactor(), stdin=io.StringIO("123\n"), stdout=out)
    assert json.loads(out.getvalue())["error"]["code"] == -32600
