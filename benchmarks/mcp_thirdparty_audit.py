"""What reaches an agent through any MCP redaction tool? A black-box egress audit.

Connects to an MCP server over stdio with the official ``mcp`` client, lists its
tools, and calls every tool that takes a text argument on each document. Every
string in every reply (JSON text blocks are parsed) is searched for every gold
value of at least ``MIN_LEN`` characters with a letter, in the five encodings of
``mcp_egress_audit``. A hit counts only if it disappears when the gold values are
masked in the input. Each hit is attributed to a tool and a JSON path, so a
reply's redacted text (where a missed value is a recall failure) is reported
apart from every other field (where a value is egress through metadata, a
mapping table or an echo of the input).

The server command comes from a JSON manifest entry (name, version, source,
command, args). The audit never sends a document anywhere but to that local
process.

    python -m benchmarks.mcp_thirdparty_audit --manifest servers.json \\
        --server safestream --corpus agent_traces wnut17 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks import corpora
from benchmarks.mcp_egress_audit import MIN_LEN, forms, found, leaves, mask

TEXT_ARGS = ("text", "content", "input", "input_text", "prompt", "data", "message", "document")
# fields whose value is the redacted text the tool exists to return
REDACTED_TEXT_HINTS = ("redacted", "anonymized", "anonymised", "scrubbed", "sanitized",
                       "masked", "cleaned", "output", "result", "text")  # fmt: skip


def text_tools(tools: list[Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """(tool, text argument, fixed extra arguments) for each tool a document can feed."""
    out = []
    for t in tools:
        schema = t.input_schema or {}
        props: dict[str, Any] = schema.get("properties", {})
        arg = next((a for a in TEXT_ARGS if props.get(a, {}).get("type") == "string"), None)
        if arg is None:
            continue
        required = [r for r in schema.get("required", []) if r != arg]
        extra: dict[str, Any] = {}
        for r in required:  # fill only required arguments that have a declared default
            if "default" in props.get(r, {}):
                extra[r] = props[r]["default"]
        if len(extra) == len(required):
            out.append((t.name, arg, extra))
    return out


def reply_payload(result: Any) -> dict[str, Any]:
    texts = [c.text for c in (result.content or []) if getattr(c, "type", "") == "text"]
    return {"content": texts, "structured": result.structured_content, "error": result.is_error}


def classify(path: str) -> str:
    """'redacted_text' for the field a redaction tool returns its output in, else 'other'."""
    last = path.split(".")[-1].split("<")[0].lower()
    if path.startswith("content[]") and "<json>" not in path:
        return "redacted_text"  # a plain-text reply is the tool's output
    return "redacted_text" if any(h in last for h in REDACTED_TEXT_HINTS) else "other"


async def audit(server: dict[str, Any], docs: list[corpora.Doc]) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=server["command"],
        args=server.get("args", []),
        env={**os.environ, **server.get("env", {})},
        cwd=server.get("cwd"),
    )
    report: dict[str, Any] = {"server": {k: server[k] for k in ("name", "version", "source")}}
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = (await session.list_tools()).tools
        report["tools_listed"] = [t.name for t in tools]
        callable_tools = text_tools(tools)
        report["tools_audited"] = {n: a for n, a, _ in callable_tools}
        results: dict[str, Any] = {}
        for name, arg, extra in callable_tools:
            by_kind: Counter[str] = Counter()
            by_path: Counter[str] = Counter()
            errors = values_checked = 0
            egressed = {"redacted_text": 0, "other": 0}
            for doc in docs:
                vals = {
                    doc.text[g.start : g.end]
                    for g in doc.spans
                    if len(doc.text[g.start : g.end].strip()) >= MIN_LEN
                    and any(c.isalpha() for c in doc.text[g.start : g.end])
                }
                if not vals:
                    continue
                real = await session.call_tool(name, {arg: doc.text, **extra})
                ctrl = await session.call_tool(name, {arg: mask(doc.text, doc.spans), **extra})
                if real.is_error:
                    errors += 1
                    continue
                real_leaves = list(leaves(reply_payload(real)))
                ctrl_leaves = [s for _p, s in leaves(reply_payload(ctrl))]
                for v in vals:
                    values_checked += 1
                    hit_kinds = set()
                    for enc, needle in forms(v).items():
                        if any(found(s, enc, needle) for s in ctrl_leaves):
                            continue
                        for path, leaf in real_leaves:
                            if not path.endswith("#key") and found(leaf, enc, needle):
                                kind = classify(path)
                                hit_kinds.add(kind)
                                by_kind[f"{kind}|{enc}"] += 1
                                by_path[path] += 1
                    for k in hit_kinds:
                        egressed[k] += 1
            results[name] = {
                "text_argument": arg,
                "values_checked": values_checked,
                "values_in_redacted_text": egressed["redacted_text"],
                "values_in_other_fields": egressed["other"],
                "calls_failed": errors,
                "events_by_kind_encoding": dict(sorted(by_kind.items())),
                "events_by_json_path": dict(sorted(by_path.items())),
            }
            print(
                f"{server['name']}.{name}: values in redacted text "
                f"{egressed['redacted_text']}/{values_checked}, in other fields "
                f"{egressed['other']}/{values_checked}, failed calls {errors}",
                flush=True,
            )
        report["results"] = results
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--server", nargs="+", required=True)
    ap.add_argument("--corpus", nargs="+", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--limit", type=int, default=0, help="first N documents per corpus")
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    servers = {s["name"]: s for s in json.loads(args.manifest.read_text(encoding="utf-8"))}
    out: dict[str, Any] = {"min_len": MIN_LEN, "results": {}}
    for name in args.server:
        for corpus in args.corpus:
            split = "all" if corpus == "agent_traces" else args.split
            docs = corpora.load(corpus, split).docs
            docs = docs[: args.limit] if args.limit else docs
            out["results"][f"{name}|{corpus}"] = asyncio.run(audit(servers[name], docs))
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
