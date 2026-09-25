"""Tests for the optional stdlib REST API (safestream_redactor.api)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from safestream_redactor import __version__
from safestream_redactor.api import dispatch, make_handler, serve
from safestream_redactor.redactor import Redactor

SAMPLE = "email me at jane@example.com or call, key=AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(scope="module")
def redactor() -> Redactor:
    return Redactor()


# --------------------------------------------------------------------------
# dispatch() — pure, no server
# --------------------------------------------------------------------------


def test_health(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "GET", "/health", b"")
    assert status == 200
    assert body == {"status": "ok"}


def test_version(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "GET", "/version", b"")
    assert status == 200
    assert body["version"] == __version__


def test_detectors_lists_tiers_and_types(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "GET", "/detectors", b"")
    assert status == 200
    assert "deterministic" in body["tiers"]
    assert "email" in body["entity_types"]


def test_redact_returns_redacted_text(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "POST", "/redact", json.dumps({"text": SAMPLE}).encode())
    assert status == 200
    assert "jane@example.com" not in body["redacted"]
    assert body["total_detections"] >= 1
    assert body["detections_by_type"]["email"] == 1


def test_scan_is_content_free(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "POST", "/scan", json.dumps({"text": SAMPLE}).encode())
    assert status == 200
    assert body["total_detections"] >= 1
    for det in body["detections"]:
        # offsets + type + confidence, but never the matched substring
        assert set(det) == {"start", "end", "entity_type", "confidence", "source"}
    # the raw email must not appear anywhere in the serialized response
    assert "jane@example.com" not in json.dumps(body)


def test_trailing_slash_and_query_are_ignored(redactor: Redactor) -> None:
    status, _ = dispatch(redactor, "GET", "/health/?foo=bar", b"")
    assert status == 200


def test_unknown_route_404(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "GET", "/nope", b"")
    assert status == 404
    assert "error" in body


def test_invalid_json_400(redactor: Redactor) -> None:
    status, body = dispatch(redactor, "POST", "/redact", b"{not json")
    assert status == 400
    assert "error" in body


def test_missing_text_field_400(redactor: Redactor) -> None:
    status, _ = dispatch(redactor, "POST", "/redact", json.dumps({"nope": 1}).encode())
    assert status == 400


def test_non_string_text_400(redactor: Redactor) -> None:
    status, _ = dispatch(redactor, "POST", "/scan", json.dumps({"text": 5}).encode())
    assert status == 400


def test_empty_body_defaults_to_missing_text(redactor: Redactor) -> None:
    status, _ = dispatch(redactor, "POST", "/redact", b"")
    assert status == 400


def test_oversized_body_413(redactor: Redactor) -> None:
    payload = json.dumps({"text": "x" * 100}).encode()
    status, body = dispatch(redactor, "POST", "/redact", payload, max_body_bytes=10)
    assert status == 413
    assert "error" in body


# --------------------------------------------------------------------------
# live server round-trip
# --------------------------------------------------------------------------


@pytest.fixture()
def live_server(redactor: Redactor):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(redactor))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _get(url: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def _post(url: str, obj: object) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_live_health(live_server: str) -> None:
    status, body = _get(f"{live_server}/health")
    assert status == 200
    assert body["status"] == "ok"


def test_live_redact_roundtrip(live_server: str) -> None:
    status, body = _post(f"{live_server}/redact", {"text": SAMPLE})
    assert status == 200
    assert "jane@example.com" not in body["redacted"]


def test_live_oversized_body_rejected(redactor: Redactor) -> None:
    # handler rejects on Content-Length before reading the body into memory
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(redactor, max_body_bytes=10))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    try:
        status, body = _post(f"http://{host}:{port}/redact", {"text": "x" * 500})
        assert status == 413
        assert "error" in body
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_live_bad_request(live_server: str) -> None:
    status, body = _post(f"{live_server}/redact", {"wrong": 1})
    assert status == 400
    assert "error" in body


def test_cli_serve_invokes_server(monkeypatch: pytest.MonkeyPatch) -> None:
    from safestream_redactor import cli

    called: dict[str, object] = {}

    def _fake_serve(redactor: object, *, host: str, port: int, max_body_bytes: int) -> None:
        called["host"] = host
        called["port"] = port
        called["max_body_bytes"] = max_body_bytes

    monkeypatch.setattr("safestream_redactor.api.serve", _fake_serve)
    rc = cli.main(["serve", "--host", "127.0.0.1", "--port", "0", "--max-body", "1234"])
    assert rc == 0
    assert called["port"] == 0
    assert called["max_body_bytes"] == 1234


def test_serve_default_redactor_is_constructed(monkeypatch: pytest.MonkeyPatch) -> None:
    # serve() with no redactor must build a default one and start the server.
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, addr: tuple[str, int], handler: object) -> None:
            captured["addr"] = addr

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr("safestream_redactor.api.ThreadingHTTPServer", _FakeServer)
    serve(host="127.0.0.1", port=12345)
    assert captured["addr"] == ("127.0.0.1", 12345)
    assert captured["closed"] is True


# --------------------------------------------------------------------------
# malformed Content-Length (F1): must fail fast with 400, never block a thread
# --------------------------------------------------------------------------

import socket as _socket  # noqa: E402
from urllib.parse import urlparse  # noqa: E402


def _raw_post_status(base_url: str, content_length: str) -> int:
    """POST with a raw, attacker-controlled Content-Length; return the status code.

    Uses a socket timeout so that if the server ever blocked on the body (the
    pre-fix ``rfile.read(-1)`` hang), the recv would time out and fail the test
    rather than hang the suite.
    """
    parsed = urlparse(base_url)
    assert parsed.hostname is not None and parsed.port is not None
    with _socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.settimeout(5)
        request = (
            "POST /redact HTTP/1.1\r\n"
            f"Host: {parsed.hostname}\r\n"
            f"Content-Length: {content_length}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        sock.sendall(request)
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    status_line = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split()
    assert len(parts) >= 2, f"no HTTP status line received (got {data!r})"
    return int(parts[1])


def test_live_negative_content_length_400(live_server: str) -> None:
    # A negative Content-Length must be rejected immediately, not passed to
    # rfile.read(-1) (which would block the worker thread until EOF).
    assert _raw_post_status(live_server, "-1") == 400


def test_live_non_numeric_content_length_400(live_server: str) -> None:
    # A non-numeric Content-Length must yield a bounded 400, not an unhandled
    # ValueError that drops the connection with no response.
    assert _raw_post_status(live_server, "not-a-number") == 400


def test_dispatch_still_enforces_max_body(redactor: Redactor) -> None:
    # The pure dispatch path still guards oversized bodies independently of the
    # handler's Content-Length pre-check.
    payload = json.dumps({"text": "x" * 100}).encode()
    status, _ = dispatch(redactor, "POST", "/redact", payload, max_body_bytes=10)
    assert status == 413
