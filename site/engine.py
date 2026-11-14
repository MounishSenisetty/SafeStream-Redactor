"""Glue between the demo page and safestream_redactor, running under Pyodide.

The browser worker (engine.js) imports this module and calls the functions below
with JSON strings; each returns a JSON string. No detection logic lives here: it
calls the same ui.core helpers the local Streamlit playground uses, the same policy
loader `--config policy.toml` uses, the same REST dispatch() and MCP server the CLI
serves, and the CLI's own main(), all from the unmodified wheel.

Settings travel as a policy-file dictionary: the page's controls and its
policy.toml editor are two views of one object, and the engine builds its
Redactor from that object exactly as `safestream redact --config policy.toml`
does (config.validate_config, policy_from_config, redactor_kwargs_from_config).

Offsets: Python indexes text by code point, JavaScript by UTF-16 unit, so every
offset handed back is converted (the two differ after any astral character such
as an emoji).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import tracemalloc
from bisect import bisect_right
from collections.abc import Callable, Iterator
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - the demo runs CPython 3.14 (Pyodide); tests run 3.10+
    import tomli as tomllib

from safestream_redactor import __version__, cli, config
from safestream_redactor.api import dispatch
from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
from safestream_redactor.entities import EntityType
from safestream_redactor.errors import SafeStreamError
from safestream_redactor.mcp_server import MCPServer
from safestream_redactor.operators import HASH_ALGORITHMS, require_crypto
from safestream_redactor.policy import RedactionMode
from safestream_redactor.redactor import Redactor
from safestream_redactor.severity import severity_for
from safestream_redactor.ui import core

_cache: dict[str, tuple[Redactor, MCPServer]] = {}


class _UserError(ValueError):
    """A problem the page should show verbatim (it never contains input text)."""


def _policy(raw: dict[str, Any]) -> dict[str, Any]:
    """The policy-file dictionary for ``raw``, validated like a --config file.

    Empty sections are dropped, so ``{}`` means every default.
    """
    data = {k: v for k, v in raw.items() if v != {}}
    try:
        config.validate_config(data)
    except ValueError as exc:
        raise _UserError(str(exc)) from exc
    return data


def _build(data: dict[str, Any], **override: Any) -> Redactor:
    """A Redactor for a validated policy dictionary, built the way the CLI builds one."""
    try:
        kwargs = config.redactor_kwargs_from_config(data)
        kwargs.update(override)
        return Redactor(policy=config.policy_from_config(data), **kwargs)
    except ImportError as exc:
        # an optional extra (spaCy, onnxruntime, cryptography): none ships in the browser
        raise _UserError(
            f"{exc} This tier or mode needs an optional extra, which this browser demo "
            "does not include. Run it locally with the extra installed."
        ) from exc
    except (ValueError, SafeStreamError) as exc:
        raise _UserError(str(exc)) from exc


def _engine(settings_json: str) -> tuple[Redactor, MCPServer]:
    """The redactor (and an MCP server around it) for these settings, built once."""
    if settings_json not in _cache:
        redactor = _build(_policy(json.loads(settings_json)))
        _cache.clear()  # one live configuration at a time
        _cache[settings_json] = (redactor, MCPServer(redactor))
    return _cache[settings_json]


def _utf16(text: str) -> Callable[[int], int]:
    """A code-point -> UTF-16 offset converter for ``text``."""
    astral = [i for i, ch in enumerate(text) if ord(ch) > 0xFFFF]
    if not astral:
        return lambda i: i
    return lambda i: i + bisect_right(astral, i - 1)


def _ok(result: Any) -> str:
    return json.dumps({"ok": True, "result": result})


def _error(exc: Exception) -> str:
    # these messages are written for people and quote settings, never input text;
    # anything else gets only its type, so an unexpected error cannot echo the input
    user_facing = isinstance(exc, (_UserError, core.SettingsError, core.InputError))
    return json.dumps({"ok": False, "error": str(exc) if user_facing else type(exc).__name__})


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _crypto_available() -> bool:
    try:
        require_crypto()
    except ImportError:
        return False
    return True


def info() -> str:
    return _ok(
        {
            "version": __version__,
            "pattern_types": list(core.PATTERN_TYPES),
            "all_types": [e.value for e in EntityType],
            "severity": {e.value: severity_for(e) for e in EntityType},
            "modes": [m.value for m in RedactionMode],
            "hash_algorithms": list(HASH_ALGORITHMS),
            "crypto": _crypto_available(),
            "chunk_size": DEFAULT_CHUNK_SIZE,
            "overlap": DEFAULT_OVERLAP,
            "starter_config": cli._STARTER_CONFIG,
            "python": sys.version.split()[0],
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
            "chunk": redactor.chunk_size,
            "overlap": redactor.overlap,
        }
    )


def check_policy(toml_text: str) -> str:
    """Parse and validate a policy.toml, and build a Redactor from it.

    Returns the policy as a dictionary (what the page's controls show), or the
    loader's own error: a TOML syntax error with its line, an unknown key with a
    suggestion, or an invalid option.
    """
    try:
        try:
            data = tomllib.loads(toml_text)
        except tomllib.TOMLDecodeError as exc:
            raise _UserError(f"Invalid TOML: {exc}") from exc
        data = _policy(data)
        _build(data)
    except Exception as exc:
        return _error(exc)
    return _ok(data)


def trace(text: str, settings_json: str, chunk: int) -> str:
    """Every pass of the streaming engine over ``text``, for the inspector."""
    try:
        core.check_text_size(text)
        base, _ = _engine(settings_json)
        sizes = core.inspector_chunk_sizes(base)
        redactor = _build(_policy(json.loads(settings_json)), chunk_size=int(chunk))
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


def determinism(text: str, settings_json: str) -> str:
    """Redact ``text`` several independent ways and fingerprint each output.

    1. the playground's path: the streaming engine at the configured chunk size;
    2. the same again, on a Redactor built from scratch;
    3. the whole text in one call (``Redactor.redact``), no streaming at all;
    4. the streaming engine fed the smallest chunk it accepts (one overlap).

    The engine's contract is that all four are byte-identical.
    """
    try:
        core.check_text_size(text)
        data = _policy(json.loads(settings_json))
        first, _ = _engine(settings_json)
        fresh = _build(data)
        small = _build(data, chunk_size=max(fresh.overlap, 1))
        runs = []

        def run(label: str, produce: Callable[[], str]) -> None:
            started = time.perf_counter()
            out = produce()
            ms = (time.perf_counter() - started) * 1000
            runs.append(
                {
                    "label": label,
                    "sha256": _sha256(out),
                    "bytes": len(out.encode("utf-8")),
                    "ms": round(ms, 1),
                }
            )

        run(
            f"streaming, {first.chunk_size:,}-character chunks",
            lambda: core.redact_text(text, core.scan(first, text)),
        )
        run(
            "streaming again, on a newly built engine", lambda: "".join(fresh.redact_stream([text]))
        )
        run("whole text in one call, no streaming", lambda: fresh.redact(text))
        run(
            f"streaming, {small.chunk_size:,}-character chunks",
            lambda: "".join(
                small.redact_stream(
                    text[i : i + small.chunk_size] for i in range(0, len(text), small.chunk_size)
                )
            ),
        )
    except Exception as exc:
        return _error(exc)
    return _ok({"runs": runs, "identical": len({r["sha256"] for r in runs}) == 1})


# --- streaming benchmark ----------------------------------------------------

_USERS = ("maria.garcia", "d.okafor", "li.wei", "a.novak", "s.iyer")


def _log_lines(total_bytes: int) -> Iterator[str]:
    """A synthetic service log of ``total_bytes`` (ASCII), generated as it is read.

    Fixed seed, so every run streams the same text. About one line in three
    carries an email, IP, card, SSN or credential for the engine to find.
    """
    seed = 7
    sent = 0
    i = 0
    while sent < total_bytes:
        seed = (seed * 1103515245 + 12345) % 2147483648
        kind = seed % 9
        user = _USERS[(seed >> 8) % len(_USERS)]
        ts = f"2026-11-02T{9 + (i // 3600) % 12:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z"
        if kind == 0:
            line = f"{ts} INFO  auth    login ok user={user}@corpmail.com ip=10.{seed % 250}.{(seed >> 4) % 250}.{(seed >> 12) % 250}\n"  # noqa: E501
        elif kind == 1:
            line = f"{ts} WARN  billing card=4111 1111 1111 1111 ssn=123-45-6789 retry={seed % 5}\n"
        elif kind == 2:
            line = f"{ts} DEBUG deploy  aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"  # noqa: E501
        else:
            line = f"{ts} INFO  api     GET /v1/orders/{10000 + seed % 90000} 200 in {seed % 90 + 3} ms\n"  # noqa: E501
        line = line[: total_bytes - sent]
        sent += len(line)
        i += 1
        yield line


def _chunked(lines: Iterator[str], size: int) -> Iterator[str]:
    """Group generated lines into reads of about ``size`` characters, like a file."""
    buf: list[str] = []
    n = 0
    for line in lines:
        buf.append(line)
        n += len(line)
        if n >= size:
            yield "".join(buf)
            buf, n = [], 0
    if buf:
        yield "".join(buf)


def bench(settings_json: str, sizes_json: str, progress: Any = None) -> str:
    """Stream generated logs of each size through ``redact_stream`` and measure it.

    Each size runs twice: once timed (throughput), once under tracemalloc (peak
    Python allocation, the measure the repository's constant-memory test uses).
    The input is generated while it is read and the output is hashed as it is
    written, so neither is ever held whole: memory is the engine's own.
    """
    try:
        sizes = [int(s) for s in json.loads(sizes_json)]
        if not sizes or min(sizes) < 1 or max(sizes) > 64 * 1024 * 1024:
            raise _UserError("Choose sizes between 1 byte and 64 MiB.")
        redactor, _ = _engine(settings_json)
        rows = []
        for n, size in enumerate(sizes):
            row: dict[str, Any] = {"bytes": size}
            for traced in (False, True):
                if progress is not None:
                    progress(n, len(sizes), "measuring memory" if traced else "timing")
                digest = hashlib.sha256()
                out_bytes = 0
                if traced:
                    tracemalloc.start()
                    tracemalloc.reset_peak()
                started = time.perf_counter()
                for piece in redactor.redact_stream(_chunked(_log_lines(size), 64 * 1024)):
                    encoded = piece.encode("utf-8")
                    digest.update(encoded)
                    out_bytes += len(encoded)
                elapsed = time.perf_counter() - started
                if traced:
                    _, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    row["peak_bytes"] = peak
                else:
                    row["seconds"] = round(elapsed, 3)
                    row["mb_per_s"] = round(size / 1e6 / elapsed, 2) if elapsed else None
                    row["out_bytes"] = out_bytes
                    row["sha256"] = digest.hexdigest()
            rows.append(row)
    except Exception as exc:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        return _error(exc)
    return _ok({"rows": rows, "chunk": redactor.chunk_size, "overlap": redactor.overlap})


# --- consoles ---------------------------------------------------------------


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


# the subcommands that make sense in a page: the others serve sockets or start a UI
_CLI_COMMANDS = ("detect", "redact", "init-config")


def run_cli(argv_json: str, files_json: str) -> str:
    """Run the real ``safestream`` command line on files that exist only in memory.

    ``files`` ({name: text}) are written to a fresh directory in Pyodide's
    in-memory file system, which becomes the working directory; the command's
    stdout, stderr and exit status are returned exactly as a terminal shows them.
    """
    argv = [str(a) for a in json.loads(argv_json)]
    files = {str(k): str(v) for k, v in json.loads(files_json).items()}
    if not argv or argv[0] not in _CLI_COMMANDS:
        return _error(_UserError(f"This page runs: safestream {' | '.join(_CLI_COMMANDS)}."))
    out, err = io.StringIO(), io.StringIO()
    workdir = tempfile.mkdtemp(prefix="safestream-cli-")
    previous = os.getcwd()
    try:
        for name, text in files.items():
            path = os.path.join(workdir, name)
            if os.path.dirname(os.path.abspath(path)) != workdir:
                raise _UserError(f"File names may not contain a directory: {name!r}")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(text)
        os.chdir(workdir)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(argv)
            except SystemExit as exc:  # argparse usage errors (2), --help (0), messages (1)
                if exc.code is None or isinstance(exc.code, int):
                    code = exc.code or 0
                else:
                    print(exc.code, file=sys.stderr)
                    code = 1
        written = {}
        for name in sorted(os.listdir(workdir)):
            path = os.path.join(workdir, name)
            if name not in files and os.path.isfile(path):
                with open(path, encoding="utf-8", errors="replace") as f:
                    written[name] = f.read()
    except Exception as exc:
        return _error(exc)
    finally:
        os.chdir(previous)
        shutil.rmtree(workdir, ignore_errors=True)
    return _ok({"exit": code, "stdout": out.getvalue(), "stderr": err.getvalue(), "files": written})
