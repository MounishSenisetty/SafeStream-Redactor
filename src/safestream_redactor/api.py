"""Optional local REST API around the core :class:`Redactor`.

The API is a thin transport adapter: it holds a single configured
:class:`~safestream_redactor.redactor.Redactor` and forwards requests to it. It
adds **no** detection or redaction logic of its own, so the HTTP path and the
CLI/library path share one implementation and produce identical results.

Only the Python standard library is used (:mod:`http.server`), so the base
package gains no runtime dependency by shipping this module.

Design choices that keep the local-first guarantees intact:

* The server binds to ``127.0.0.1`` by default — it is a loopback convenience
  for local tools and containers, not an internet-facing service.
* Request lines and bodies are **never** logged (they can contain the very
  secrets being redacted); :meth:`log_message` is silenced.
* ``/scan`` returns offsets and entity types, never the matched substring, so a
  scan response stays content-free even though the caller already holds the
  text.
* Request bodies larger than ``max_body_bytes`` are rejected with ``413`` before
  being read into memory.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

from safestream_redactor import __version__
from safestream_redactor.entities import EntityType

if TYPE_CHECKING:
    from safestream_redactor.redactor import Redactor

# Redaction over the API is whole-string (held in memory), unlike the streaming
# file path. Cap the body so a single request can't exhaust memory; large
# inputs should use the streaming CLI/library API instead.
DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MiB


def dispatch(
    redactor: Redactor,
    method: str,
    path: str,
    body: bytes,
    *,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> tuple[int, dict[str, object]]:
    """Route one request to the redactor and return ``(status, json_payload)``.

    Pure function of its arguments (no I/O), so it is unit-testable without a
    running server. The HTTP handler is a thin wrapper over this.
    """
    route = path.split("?", 1)[0].rstrip("/") or "/"

    if method == "GET" and route == "/health":
        return 200, {"status": "ok"}
    if method == "GET" and route == "/version":
        return 200, {"tool": "safestream-redactor", "version": __version__}
    if method == "GET" and route == "/detectors":
        return 200, {
            "tiers": redactor.detector_names,
            "entity_types": [e.value for e in EntityType],
        }

    if method == "POST" and route in ("/redact", "/scan"):
        if len(body) > max_body_bytes:
            return 413, {"error": f"request body exceeds {max_body_bytes} bytes"}
        try:
            data = json.loads(body or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return 400, {"error": "request body must be valid JSON"}
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return 400, {"error": "body must be a JSON object with a string 'text' field"}
        text: str = data["text"]

        detections = redactor.detect(text)
        by_type: dict[str, int] = {}
        for det in detections:
            by_type[det.entity_type.value] = by_type.get(det.entity_type.value, 0) + 1

        if route == "/redact":
            return 200, {
                "redacted": redactor.policy.apply(text, detections),
                "total_detections": len(detections),
                "detections_by_type": dict(sorted(by_type.items())),
            }
        # /scan — content-free: offsets + types only, never the matched text
        return 200, {
            "total_detections": len(detections),
            "detections_by_type": dict(sorted(by_type.items())),
            "detections": [
                {
                    "start": d.start,
                    "end": d.end,
                    "entity_type": d.entity_type.value,
                    "confidence": round(d.confidence, 4),
                    "source": d.source,
                }
                for d in detections
            ],
        }

    return 404, {"error": f"no route for {method} {route}"}


def make_handler(
    redactor: Redactor, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class bound to ``redactor``."""

    class _Handler(BaseHTTPRequestHandler):
        server_version = f"SafeStreamRedactor/{__version__}"
        protocol_version = "HTTP/1.1"

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > max_body_bytes:
                # refuse before reading the oversized body into memory
                self._send(413, {"error": f"request body exceeds {max_body_bytes} bytes"})
                return
            body = self.rfile.read(length) if length else b""
            status, payload = dispatch(
                redactor, method, self.path, body, max_body_bytes=max_body_bytes
            )
            self._send(status, payload)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def _send(self, status: int, payload: dict[str, object]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:
            # Never log request lines/paths/bodies: they may embed secrets.
            pass

    return _Handler


def serve(
    redactor: Redactor | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ThreadingHTTPServer:
    """Start a blocking REST server. Returns only when interrupted.

    Pass a preconfigured ``redactor`` to control detection/redaction policy; the
    default is a stock :class:`Redactor`. Binds to loopback by default.
    """
    if redactor is None:
        from safestream_redactor.redactor import Redactor

        redactor = Redactor()
    httpd = ThreadingHTTPServer((host, port), make_handler(redactor, max_body_bytes))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive Ctrl-C only
        pass
    finally:
        httpd.server_close()
    return httpd
