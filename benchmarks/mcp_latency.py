"""Per-call cost of the guardrail by transport and payload size.

Transports: ``inproc`` (``MCPServer.handle`` in this process), ``stdio`` (the official
``mcp`` SDK client against ``safestream mcp-serve`` in a child process) and ``rest``
(HTTP against ``safestream serve`` on loopback). Payloads are AgentTrace text cut to
size. Calls per cell: min(1000, max(20, 64 MiB / payload)) after 5 warm-up calls.
The tool is ``scan`` for MCP and ``/scan`` for REST (detection plus serialisation).

    python -m benchmarks.mcp_latency --transports inproc stdio rest --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from benchmarks import corpora

SIZES = [256, 4096, 65536, 1 << 20, 4 << 20]
WARMUP = 5


def payload(size: int) -> str:
    text = "\n".join(d.text for d in corpora.load("agent_traces").docs)
    while len(text.encode()) < size:
        text += "\n" + text
    out = text.encode()[:size].decode("utf-8", "ignore")
    return out


def calls_for(size: int) -> int:
    return min(1000, max(20, (64 << 20) // size))


def summary(lat: list[float], wall: float) -> dict[str, float]:
    q = statistics.quantiles(lat, n=100)
    return {
        "calls": len(lat),
        "p50_ms": 1000 * statistics.median(lat),
        "p95_ms": 1000 * q[94],
        "p99_ms": 1000 * q[98],
        "calls_per_s": len(lat) / wall,
    }


def run_inproc(text: str, n: int) -> tuple[list[float], float]:
    from safestream_redactor.mcp_server import MCPServer

    server = MCPServer()
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
    msg["params"] = {"name": "scan", "arguments": {"text": text}}
    for _ in range(WARMUP):
        server.handle(msg)
    lat = []
    t0 = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        json.dumps(server.handle(msg))  # the bytes a transport would write
        lat.append(time.perf_counter() - t)
    return lat, time.perf_counter() - t0


async def _stdio(text: str, n: int) -> tuple[list[float], float, float]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "safestream_redactor", "mcp-serve"],
        env=dict(os.environ),
    )
    t_start = time.perf_counter()
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        cold = time.perf_counter() - t_start
        for _ in range(WARMUP):
            await session.call_tool("scan", {"text": text})
        lat = []
        t0 = time.perf_counter()
        for _ in range(n):
            t = time.perf_counter()
            await session.call_tool("scan", {"text": text})
            lat.append(time.perf_counter() - t)
        return lat, time.perf_counter() - t0, cold


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run_rest(text: str, n: int) -> tuple[list[float], float, float]:
    port = _free_port()
    t_start = time.perf_counter()
    proc = subprocess.Popen(
        [sys.executable, "-m", "safestream_redactor", "serve", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        while True:  # cold start: process launch to the first /health reply
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", "/health")
                c.getresponse().read()
                break
            except OSError:
                time.sleep(0.01)
        cold = time.perf_counter() - t_start
        body = json.dumps({"text": text}).encode()
        headers = {"Content-Type": "application/json"}
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=600)

        def call() -> None:
            conn.request("POST", "/scan", body, headers)
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200, resp.status

        for _ in range(WARMUP):
            call()
        lat = []
        t0 = time.perf_counter()
        for _ in range(n):
            t = time.perf_counter()
            call()
            lat.append(time.perf_counter() - t)
        return lat, time.perf_counter() - t0, cold
    finally:
        proc.terminate()
        proc.wait()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--transports", nargs="+", default=["inproc", "stdio", "rest"])
    ap.add_argument("--sizes", nargs="+", type=int, default=SIZES)
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    from benchmarks.harness import environment
    from benchmarks.mcp_egress_audit import _code_commit

    report: dict[str, Any] = {"environment": environment(), "code": _code_commit(), "results": {}}
    for size in args.sizes:
        text, n = payload(size), calls_for(size)
        for tr in args.transports:
            cold = None
            if tr == "inproc":
                lat, wall = run_inproc(text, n)
            elif tr == "stdio":
                lat, wall, cold = asyncio.run(_stdio(text, n))
            else:
                lat, wall, cold = run_rest(text, n)
            row = summary(lat, wall) | {"cold_start_s": cold, "payload_bytes": len(text.encode())}
            report["results"][f"{tr}|{size}"] = row
            print(
                f"{tr:6} {size:>8} B  p50 {row['p50_ms']:.2f} ms  p99 {row['p99_ms']:.2f} ms",
                flush=True,
            )
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
