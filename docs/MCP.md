# MCP Server

SafeStream ships a local [Model Context Protocol](https://modelcontextprotocol.io)
server so an AI agent can check text for secrets and PII as a tool — without the
raw secret ever crossing the tool boundary.

```bash
safestream mcp-serve                 # stdio JSON-RPC 2.0, all tiers
safestream mcp-serve --config policy.toml
```

It speaks newline-delimited JSON-RPC 2.0 over stdio, runs entirely offline (the
network guard stays installed), and opens no sockets of its own.

## Client configuration

Point any MCP client at the command. For example:

```json
{
  "mcpServers": {
    "safestream": { "command": "safestream", "args": ["mcp-serve"] }
  }
}
```

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `scan` | `{ "text": "..." }` | finding metadata: `type`, `start`, `end`, `length`, `confidence`, `severity`, `detector` — **no secret text** |
| `redact` | `{ "text": "..." }` | `redacted_text` (secrets removed) + content-free counts |
| `explain_detection` | `{ "text": "..." }` | per-finding rationale: type, severity, detector, confidence, context note — **no secret text** |
| `detectors` | `{}` | active tiers + their streaming requirements + overlap |
| `health` | `{}` | version, tiers, protocol, offline status |

## Security model

The cardinal rule: a detection tool must not become an exfiltration channel.

- `scan` and `explain_detection` return **metadata only**. An agent learns *that*
  an AWS key sits at characters 40–60 with critical severity, never what the key
  is. This is enforced by construction and covered by
  `tests/test_mcp.py::test_scan_never_returns_the_secret`.
- `redact` is safe because it returns text with the secrets already removed.
- Every text input is size-capped (`MAX_TEXT_BYTES`, 4 MiB); whole files go
  through the streaming CLI, not the in-memory tool path.
- Internal errors are returned as JSON-RPC errors with the exception *type* only,
  never a message that could echo input content.

## Example session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}

→ {"jsonrpc":"2.0","id":2,"method":"tools/call",
   "params":{"name":"scan","arguments":{"text":"key AKIA...EXAMPLE"}}}
← {"jsonrpc":"2.0","id":2,"result":{"structuredContent":
   {"count":1,"findings":[{"type":"aws_key","start":4,"end":24,
     "severity":"critical","detector":"deterministic","redacted":true}]}}}
```
