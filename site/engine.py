"""Glue between the demo page and safestream_redactor, running under Pyodide.

The browser worker (engine.js) imports this module and calls the functions below
with JSON strings; each returns a JSON string. No detection logic lives here: it
calls the same ui.core helpers the local Streamlit playground uses, and the same
REST dispatch() and MCP server the CLI serves, from the unmodified PyPI wheel.

Offsets: Python indexes text by code point, JavaScript by UTF-16 unit, so every
offset handed back is converted (the two differ after any astral character such
as an emoji).
"""

from __future__ import annotations

import json
import time
from bisect import bisect_right
from typing import Any

from safestream_redactor import __version__
from safestream_redactor.api import dispatch
from safestream_redactor.entities import EntityType
from safestream_redactor.mcp_server import MCPServer
from safestream_redactor.redactor import Redactor
from safestream_redactor.ui import core

_cache: dict[str, tuple[Redactor, MCPServer]] = {}


def _settings(raw: dict[str, Any]) -> core.Settings:
    types = raw.get("types")
    return core.Settings(
        min_confidence=float(raw.get("min_confidence", 0.5)),
        chunk_size=int(raw.get("chunk_size", core.DEFAULT_CHUNK_SIZE)),
        types=None if types is None else tuple(types),
        use_entropy=bool(raw.get("use_entropy", True)),
        use_names=bool(raw.get("use_names", False)),
        custom_words=core.parse_rules(raw.get("custom_words", "")),
        custom_patterns=core.parse_rules(raw.get("custom_patterns", "")),
        style=core.RedactStyle(raw.get("style", "replace")),
        replacement=str(raw.get("replacement", "[REDACTED]")),
        keep_last=int(raw.get("keep_last", 4)),
        hash_key=str(raw.get("hash_key", "")),
    )


def _engine(settings_json: str) -> tuple[Redactor, MCPServer]:
    """The redactor (and an MCP server around it) for these settings, built once."""
    if settings_json not in _cache:
        redactor = core.build_redactor(_settings(json.loads(settings_json)))
        _cache.clear()  # one live configuration at a time
        _cache[settings_json] = (redactor, MCPServer(redactor))
    return _cache[settings_json]


def _utf16(text: str) -> Any:
    """A code-point -> UTF-16 offset converter for ``text``."""
    astral = [i for i, ch in enumerate(text) if ord(ch) > 0xFFFF]
    if not astral:
        return lambda i: i
    return lambda i: i + bisect_right(astral, i - 1)


def _ok(result: Any) -> str:
    return json.dumps({"ok": True, "result": result})


def _error(exc: Exception) -> str:
    # SettingsError / InputError messages are written for people; others get the type
    user_facing = isinstance(exc, (core.SettingsError, core.InputError))
    return json.dumps({"ok": False, "error": str(exc) if user_facing else type(exc).__name__})


def info() -> str:
    return _ok(
        {
            "version": __version__,
            "pattern_types": list(core.PATTERN_TYPES),
            "all_types": [e.value for e in EntityType],
        }
    )


def analyze(text: str, settings_json: str) -> str:
    """Findings and redacted output for ``text``, through the streaming engine."""
    try:
        core.check_text_size(text)
        redactor, _ = _engine(settings_json)
        started = time.perf_counter()
        findings = core.scan(redactor, text)
        redacted = core.redact_text(text, findings)
        elapsed = (time.perf_counter() - started) * 1000
    except Exception as exc:
        return _error(exc)
    at = _utf16(text)
    return _ok(
        {
            "findings": [
                {
                    "type": f.entity_type,
                    "severity": f.severity,
                    "start": at(f.start),
                    "end": at(f.end),
                    "line": f.line,
                    "column": f.column,
                    "confidence": round(f.confidence, 2),
                    "detector": f.source,
                    "replacement": f.replacement,
                }
                for f in findings
            ],
            "redacted": redacted,
            "ms": round(elapsed, 1),
            "tiers": redactor.detector_names,
        }
    )


def trace(text: str, settings_json: str, chunk: int) -> str:
    """Every pass of the streaming engine over ``text``, for the inspector."""
    try:
        core.check_text_size(text)
        base, _ = _engine(settings_json)
        sizes = core.inspector_chunk_sizes(base)
        settings = _settings({**json.loads(settings_json), "chunk_size": int(chunk)})
        redactor = core.build_redactor(settings)
        passes = list(core.trace_chunks(redactor, text))
    except Exception as exc:
        return _error(exc)
    at = _utf16(text)
    return _ok(
        {
            "sizes": list(sizes),
            "overlap": redactor.overlap,
            "chunk": redactor.chunk_size,
            "passes": [
                {
                    "window": [at(c.window_start), at(c.window_end)],
                    "emit": [at(c.emit_start), at(c.emit_end)],
                    "planned_end": at(c.planned_end),
                    "carried": c.carried,
                    "retreated_by": c.retreated_by,
                    "deferred": c.deferred_passes,
                    "lines": [c.line_start, c.line_end],
                    "ms": round(c.detect_ms, 1),
                    "straddlers": [c.findings[j].entity_type for j in c.straddlers],
                    "findings": [
                        {
                            "type": f.entity_type,
                            "severity": f.severity,
                            "start": at(f.start),
                            "end": at(f.end),
                            "replacement": f.replacement,
                        }
                        for f in c.findings
                    ],
                }
                for c in passes
            ],
        }
    )


def rest(method: str, path: str, body: str, settings_json: str) -> str:
    """One request to the REST API, answered by the same dispatch() `safestream serve` uses."""
    try:
        redactor, _ = _engine(settings_json)
        status, payload = dispatch(redactor, method, path, body.encode("utf-8"))
    except Exception as exc:
        return _error(exc)
    return _ok({"status": status, "body": payload})


def mcp(message: str, settings_json: str) -> str:
    """One JSON-RPC message to the MCP server, as `safestream mcp-serve` handles it."""
    try:
        _, server = _engine(settings_json)
        reply = server.handle(json.loads(message))
    except json.JSONDecodeError:
        parse_error = {"code": -32700, "message": "Parse error"}
        return _ok({"jsonrpc": "2.0", "id": None, "error": parse_error})
    except Exception as exc:
        return _error(exc)
    return _ok(reply)
