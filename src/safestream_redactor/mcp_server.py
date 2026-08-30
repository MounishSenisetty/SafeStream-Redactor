"""A local, offline Model Context Protocol (MCP) server around the redactor.

MCP lets an AI agent call tools over a JSON-RPC 2.0 stream. This server exposes
SafeStream's detection and redaction as tools so an assistant can check text for
secrets and PII *without the raw secret ever crossing the tool boundary*.

Security model
--------------

The cardinal rule here is that a detection tool must not become a secret
exfiltration channel. So:

* ``scan`` and ``explain_detection`` return only **metadata** about each finding
  — entity type, character offsets, confidence, severity, detector — and never
  the matched substring. An agent learns *that* an AWS key sits at offset 40,
  not what the key is.
* ``redact`` returns text with the secrets already removed, which is safe by
  construction, plus content-free counts.
* Every tool input is size-capped (:data:`MAX_TEXT_BYTES`) so a client cannot
  push unbounded text through the in-memory tool path (the streaming file path
  is for large inputs).

The server is transport-pure: :meth:`MCPServer.handle` maps one JSON-RPC message
to its reply (or ``None`` for a notification), so it is fully testable without a
pipe. :func:`serve_stdio` wraps it in the newline-delimited stdio loop MCP uses.

This runs entirely locally; it opens no network sockets of its own.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

from safestream_redactor import __version__
from safestream_redactor.redactor import Redactor
from safestream_redactor.report import RedactionStats
from safestream_redactor.severity import severity_for

PROTOCOL_VERSION = "2024-11-05"

# Largest text accepted by an in-memory tool call. Agents pass snippets here;
# whole files go through the streaming CLI, not the tool boundary.
MAX_TEXT_BYTES = 4 * 1024 * 1024

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class MCPError(Exception):
    """A JSON-RPC error to return to the client (never leaks secret content)."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


ToolHandler = Callable[["MCPServer", dict[str, Any]], dict[str, Any]]


class MCPServer:
    """Dispatches MCP JSON-RPC messages against a configured :class:`Redactor`."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or Redactor()
        self._initialized = False
        self._tools: dict[str, tuple[dict[str, Any], ToolHandler]] = {}
        self._register_tools()

    # -- tool registry ------------------------------------------------------

    def _register_tools(self) -> None:
        text_input = {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "text to analyse (kept local)"}
            },
            "required": ["text"],
        }
        self._tools = {
            "scan": (
                {
                    "description": (
                        "Detect PII and credentials in text. Returns finding metadata "
                        "(type, location, confidence, severity, detector) only — never "
                        "the matched secret itself."
                    ),
                    "inputSchema": text_input,
                },
                MCPServer._tool_scan,
            ),
            "redact": (
                {
                    "description": (
                        "Return the text with all detected secrets/PII redacted, plus "
                        "content-free per-type counts."
                    ),
                    "inputSchema": text_input,
                },
                MCPServer._tool_redact,
            ),
            "explain_detection": (
                {
                    "description": (
                        "Explain why each span was flagged (type, severity, detector, "
                        "confidence and how context adjusted it). No secret text."
                    ),
                    "inputSchema": text_input,
                },
                MCPServer._tool_explain,
            ),
            "detectors": (
                {
                    "description": "List active detector tiers and their streaming requirements.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                MCPServer._tool_detectors,
            ),
            "health": (
                {
                    "description": "Server health: version, active tiers, protocol, offline.",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                MCPServer._tool_health,
            ),
        }

    # -- JSON-RPC dispatch --------------------------------------------------

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Map one JSON-RPC request to its response, or ``None`` for a notification."""
        if message.get("jsonrpc") != "2.0" or "method" not in message:
            return _error_response(message.get("id"), INVALID_REQUEST, "invalid JSON-RPC request")
        method = message["method"]
        msg_id = message.get("id")
        is_notification = "id" not in message
        try:
            result = self._dispatch(method, message.get("params") or {})
        except MCPError as exc:
            return None if is_notification else _error_response(msg_id, exc.code, exc.message)
        except Exception as exc:
            # Never surface a raw exception string that might echo input content.
            return (
                None
                if is_notification
                else _error_response(
                    msg_id, INTERNAL_ERROR, f"internal error: {type(exc).__name__}"
                )
            )
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            self._initialized = True
            return {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "safestream-redactor", "version": __version__},
            }
        if method in ("notifications/initialized", "initialized"):
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {
                "tools": [
                    {"name": name, **meta} for name, (meta, _handler) in sorted(self._tools.items())
                ]
            }
        if method == "tools/call":
            return self._call_tool(params)
        raise MCPError(METHOD_NOT_FOUND, f"unknown method {method!r}")

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or name not in self._tools:
            raise MCPError(INVALID_PARAMS, f"unknown tool {name!r}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise MCPError(INVALID_PARAMS, "arguments must be an object")
        _meta, handler = self._tools[name]
        payload = handler(self, arguments)
        # MCP tool results carry a `content` array; we return the structured
        # payload as a JSON text block plus `structuredContent` for clients that
        # parse it directly. Neither ever contains matched secret text.
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload,
            "isError": False,
        }

    # -- tool inputs --------------------------------------------------------

    @staticmethod
    def _require_text(arguments: dict[str, Any]) -> str:
        text = arguments.get("text")
        if not isinstance(text, str):
            raise MCPError(INVALID_PARAMS, "expected a string 'text' argument")
        if len(text.encode("utf-8", "ignore")) > MAX_TEXT_BYTES:
            raise MCPError(
                INVALID_PARAMS,
                f"text exceeds the {MAX_TEXT_BYTES}-byte tool limit; use the streaming CLI instead",
            )
        return text

    # -- tools --------------------------------------------------------------

    def _tool_scan(self, arguments: dict[str, Any]) -> dict[str, Any]:
        text = self._require_text(arguments)
        detections = self.redactor.detect(text)
        findings = [
            {
                "type": det.entity_type.value,
                "start": det.start,
                "end": det.end,
                "length": det.end - det.start,
                "confidence": round(det.confidence, 3),
                "severity": severity_for(det.entity_type),
                "detector": det.source,
                "redacted": True,  # this span would be redacted by `redact`
            }
            for det in detections
        ]
        return {"count": len(findings), "findings": findings}

    def _tool_redact(self, arguments: dict[str, Any]) -> dict[str, Any]:
        text = self._require_text(arguments)
        stats = RedactionStats()
        detections = self.redactor.detect(text)
        redacted = self.redactor.policy.apply(text, detections)
        stats.add_segment(text, redacted, detections)
        return {
            "redacted_text": redacted,
            "total_detections": stats.total,
            "detections_by_type": dict(sorted(stats.counts.items())),
        }

    def _tool_explain(self, arguments: dict[str, Any]) -> dict[str, Any]:
        text = self._require_text(arguments)
        detections = self.redactor.detect(text)
        explained = [
            {
                "type": det.entity_type.value,
                "start": det.start,
                "end": det.end,
                "confidence": round(det.confidence, 3),
                "severity": severity_for(det.entity_type),
                "detector": det.source,
                # meta may carry an entropy figure or a "boosted"/"suppressed"
                # context note; none of it is the secret text.
                "context": det.meta.get("context"),
                "notes": {k: v for k, v in det.meta.items() if k != "context"},
            }
            for det in detections
        ]
        return {"count": len(explained), "explanations": explained}

    def _tool_detectors(self, arguments: dict[str, Any]) -> dict[str, Any]:
        from safestream_redactor.detectors.base import requirements_of

        tiers = []
        for det in self.redactor._detectors:
            req = requirements_of(det)
            tiers.append(
                {
                    "name": det.name,
                    "max_span": req.max_span,
                    "left_context": req.left_context,
                    "right_context": req.right_context,
                    "streaming_safe": req.streaming_safe,
                }
            )
        return {
            "tiers": tiers,
            "min_safe_overlap": self.redactor.min_safe_overlap,
            "configured_overlap": self.redactor.overlap,
        }

    def _tool_health(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "protocol": PROTOCOL_VERSION,
            "tiers": self.redactor.detector_names,
            "offline": True,
            "chunk_size": self.redactor.chunk_size,
            "overlap": self.redactor.overlap,
        }


def _error_response(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def serve_stdio(
    redactor: Redactor | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Run the newline-delimited JSON-RPC stdio loop MCP clients speak.

    Reads one JSON object per line from ``stdin``, writes one JSON response per
    line to ``stdout``, until EOF. Notifications (messages with no ``id``)
    produce no output. A malformed line yields a JSON-RPC parse error rather
    than crashing the loop.
    """
    server = MCPServer(redactor)
    infile = stdin or sys.stdin
    outfile = stdout or sys.stdout
    for line in infile:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write(outfile, _error_response(None, PARSE_ERROR, "parse error"))
            continue
        if not isinstance(message, dict):
            _write(outfile, _error_response(None, INVALID_REQUEST, "expected a JSON object"))
            continue
        response = server.handle(message)
        if response is not None:
            _write(outfile, response)


def _write(outfile: TextIO, obj: dict[str, Any]) -> None:
    outfile.write(json.dumps(obj, ensure_ascii=False) + "\n")
    outfile.flush()
