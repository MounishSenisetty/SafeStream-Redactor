"""Differential egress audit: does any gold value reach an agent through a tool reply?

For every document, every tool reply that is meant to be content-free is collected:
MCP ``scan``, ``explain_detection``, ``detectors`` and ``health``, REST ``/scan``, and
SARIF built from the same detections. Each reply's string leaves are searched for
every gold value of at least ``MIN_LEN`` characters, in five encodings: raw,
case-folded, whitespace-normalised, base64 and hex.

A hit counts as **egress** only if it disappears when the gold values are masked
in the input (plant -> call -> search). A leaf that also matches the masked input
is tool vocabulary (an entity type, a detector name), not a leak.

Works against any checkout: put that checkout's ``src`` first on ``PYTHONPATH`` to
audit it (the report records the commit of the code it imported).

    PYTHONPATH=/path/to/checkout/src python -m benchmarks.mcp_egress_audit \\
        --corpus agent_traces wnut17 --tiers pattern gazetteer --json out.json
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from benchmarks import corpora

MIN_LEN = 3
ONNX_DIR = corpora.ROOT / "models" / "ner"
TIERS: dict[str, dict[str, Any]] = {
    "pattern": {},
    "gazetteer": {"use_gazetteer": True},
    "onnx": {
        "use_onnx": True,
        "onnx_model": str(ONNX_DIR / "model.int8.onnx"),
        "onnx_vocab": str(ONNX_DIR / "tokenizer.json"),
        "onnx_labels": str(ONNX_DIR / "labels.json"),
    },
    "spacy": {"use_ner": True},
}
ENCODINGS = ("raw", "casefold", "whitespace", "base64", "hex")


def leaves(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """``(json path, string)`` for every string key and value in a reply."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{path}.{k}#key", str(k)
            yield from leaves(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for v in obj:
            yield from leaves(v, f"{path}[]")
    elif isinstance(obj, str):
        # MCP repeats structuredContent as a JSON text block: search it as JSON
        if obj[:1] in "{[":
            try:
                yield from leaves(json.loads(obj), path + "<json>")
                return
            except ValueError:
                pass
        yield path, obj


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().casefold()


def forms(value: str) -> dict[str, str]:
    raw = value.encode("utf-8")
    return {
        "raw": value,
        "casefold": value.casefold(),
        "whitespace": _ws(value),
        "base64": base64.b64encode(raw).decode().rstrip("="),
        "hex": raw.hex(),
    }


def found(leaf: str, enc: str, needle: str) -> bool:
    if enc == "raw":
        return needle in leaf
    if enc in ("casefold", "hex"):
        return needle in leaf.casefold()
    if enc == "whitespace":
        return needle in _ws(leaf)
    return needle in leaf  # base64 is case-sensitive


def replies(server: Any, redactor: Any, text: str) -> dict[str, Any]:
    from safestream_redactor import __version__
    from safestream_redactor.api import dispatch
    from safestream_redactor.sarif import Finding, build_sarif

    def call(name: str) -> Any:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
        msg["params"] = {"name": name, "arguments": {"text": text} if name != "health" else {}}
        return server.handle(msg)["result"]

    dets = redactor.detect(text)
    sarif = build_sarif(
        [Finding(d.entity_type, d.start, d.end, d.confidence, d.source) for d in dets],
        version=__version__,
    )
    return {
        "mcp.scan": call("scan"),
        "mcp.explain_detection": call("explain_detection"),
        "mcp.detectors": call("detectors"),
        "mcp.health": call("health"),
        "rest./scan": dispatch(redactor, "POST", "/scan", json.dumps({"text": text}).encode())[1],
        "sarif": sarif,
    }


def mask(text: str, spans: list[corpora.Gold]) -> str:
    chars = list(text)
    for g in spans:
        for i in range(g.start, g.end):
            if not chars[i].isspace():
                chars[i] = "x"
    return "".join(chars)


def audit(docs: list[corpora.Doc], redactor: Any) -> dict[str, Any]:
    from safestream_redactor.mcp_server import MCPServer

    server = MCPServer(redactor)
    server.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
    # schema keys: every key any reply can carry, from probe documents of every kind
    probes = [d.text for d in corpora.load("agent_traces").docs[:16]]
    schema = {
        leaf
        for text in probes
        for reply in replies(server, redactor, text).values()
        for path, leaf in leaves(reply)
        if path.endswith("#key")
    }
    events: Counter[str] = Counter()
    by_path: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    docs_with_egress = 0
    values_checked = 0
    values_egressed = 0
    for doc in docs:
        values = {doc.text[g.start : g.end]: g.type for g in doc.spans}
        values = {v: t for v, t in values.items() if len(v.strip()) >= MIN_LEN}
        if not values:
            continue
        real = replies(server, redactor, doc.text)
        control = replies(server, redactor, mask(doc.text, doc.spans))
        ctrl = {tool: [s for _p, s in leaves(reply)] for tool, reply in control.items()}
        hit_doc = False
        for value, etype in values.items():
            values_checked += 1
            hit_value = False
            for enc, needle in forms(value).items():
                for tool, reply in real.items():
                    if any(found(s, enc, needle) for s in ctrl[tool]):
                        continue  # vocabulary, present without the value too
                    for path, leaf in leaves(reply, tool):
                        if path.endswith("#key") and leaf in schema:
                            continue
                        if found(leaf, enc, needle):
                            events[f"{tool}|{enc}"] += 1
                            by_path[path] += 1
                            by_type[etype] += 1
                            hit_value = True
            values_egressed += hit_value
            hit_doc |= hit_value
        docs_with_egress += hit_doc
    return {
        "docs": len(docs),
        "docs_with_egress": docs_with_egress,
        "values_checked": values_checked,
        "values_egressed": values_egressed,
        "events_by_tool_encoding": dict(sorted(events.items())),
        "events_by_json_path": dict(sorted(by_path.items())),
        "events_by_gold_type": dict(sorted(by_type.items())),
    }


def _code_commit() -> dict[str, Any]:
    import safestream_redactor

    src = Path(safestream_redactor.__file__).resolve().parents[2]
    git = ["git", "-C", str(src)]
    commit = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True).stdout
    dirty = subprocess.run([*git, "status", "--porcelain", "src"], capture_output=True, text=True)
    return {"code_root": str(src), "commit": commit.strip(), "src_dirty": bool(dirty.stdout)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", nargs="+", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--tiers", nargs="+", default=list(TIERS), choices=list(TIERS))
    ap.add_argument("--limit", type=int, default=0, help="first N documents per corpus (0: all)")
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    from safestream_redactor import Redactor

    report: dict[str, Any] = {"code": _code_commit(), "min_len": MIN_LEN, "results": {}}
    for tier in args.tiers:
        redactor = Redactor(load_plugins=False, backend="native", **TIERS[tier])
        for name in args.corpus:
            split = "all" if name in ("agent_traces",) else args.split
            docs = corpora.load(name, split).docs
            docs = docs[: args.limit] if args.limit else docs
            res = audit(docs, redactor)
            report["results"][f"{tier}|{name}"] = res
            print(f"{tier:9} {name:14} egressed {res['values_egressed']}/{res['values_checked']}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
