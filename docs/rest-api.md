# REST API

SafeStream-Redactor ships an **optional** local REST API. It is a thin
transport adapter around the same `Redactor` used by the CLI and the Python
library — it adds no detection or redaction logic of its own, so an HTTP request
and a library call produce identical results.

The server uses only the Python standard library (`http.server`), so **no extra
dependency** is required to run it.

## Design principles

- **Local-first.** Binds to `127.0.0.1` (loopback) by default. It is a
  convenience for local tools and containers, not an internet-facing service.
  Put it behind a reverse proxy with authentication before exposing it.
- **No secret leakage.** Request lines and bodies are never logged. `/scan`
  returns offsets and entity types only — never the matched substring — so its
  responses stay content-free.
- **Bounded memory.** Redaction over the API holds the request text in memory
  (unlike the streaming file path), so bodies larger than the limit (8 MiB by
  default) are rejected with `413`. For large inputs, use the streaming CLI or
  `Redactor.redact_file`.
- **Connection hygiene.** Any rejected request closes its connection, so an
  unread body can never be parsed as a follow-up request on a keep-alive socket.
  Chunked bodies (`Transfer-Encoding`) are refused with `411`; send
  `Content-Length`. Each connection has a 30-second idle timeout
  (`serve(..., timeout=...)`), so a stalled client cannot hold a server thread.
- **Loopback by default.** `safestream serve --host` with a non-loopback address
  prints a warning: the API has no authentication of its own.

## Start the server

```bash
# stock detectors, loopback:8000
safestream serve

# custom policy, custom bind, 1 MiB body cap
safestream serve --config policy.toml --host 127.0.0.1 --port 8080 --max-body 1048576
```

Programmatically:

```python
from safestream_redactor.api import serve
from safestream_redactor import Redactor, RedactionPolicy, EntityType

serve(Redactor(policy=RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})))
```

## Endpoints

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/health` | — | `{"status": "ok"}` |
| `GET` | `/version` | — | `{"tool": "safestream-redactor", "version": "..."}` |
| `GET` | `/detectors` | — | active tier names + all supported entity types |
| `POST` | `/redact` | `{"text": "..."}` | `{"redacted", "total_detections", "detections_by_type"}` |
| `POST` | `/scan` | `{"text": "..."}` | `{"total_detections", "detections_by_type", "detections": [...]}` |

`/scan` detection objects contain `start`, `end`, `entity_type`, `confidence`,
and `source` — no matched text.

### Errors

| Status | Meaning |
|---|---|
| `400` | body is not valid JSON, or has no string `text` field |
| `411` | chunked request body; send `Content-Length` instead |
| `413` | request body exceeds the configured limit |
| `404` | no route for that method/path |

## Examples

```bash
curl -s http://127.0.0.1:8000/health
# {"status": "ok"}

curl -s -X POST http://127.0.0.1:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'
# {"redacted": "email [REDACTED] key [REDACTED]", "total_detections": 2,
#  "detections_by_type": {"aws_key": 1, "email": 1}}

curl -s -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"text": "ssn 123-45-6789"}'
# {"total_detections": 1, "detections_by_type": {"ssn": 1},
#  "detections": [{"start": 4, "end": 15, "entity_type": "ssn",
#                  "confidence": 0.9, "source": "deterministic"}]}
```

## Docker

The same image can run the API instead of a one-shot redaction:

```bash
docker run --rm -p 127.0.0.1:8000:8000 safestream-redactor serve --host 0.0.0.0 --port 8000
```

Bind the published port to `127.0.0.1` on the host (as above) unless you have
added authentication in front of it. Inside the container the server must bind
`0.0.0.0` to be reachable through the port mapping.

See [architecture/mermaid/rest-api.md](architecture/mermaid/rest-api.md) for the
component diagram.
