# SafeStream-Redactor

[![CI](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![License](https://img.shields.io/pypi/l/safestream-redactor.svg)](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/LICENSE)
[![Live demo](https://img.shields.io/badge/demo-try%20it%20in%20your%20browser-3b4fd8)](https://mounishsenisetty.github.io/SafeStream-Redactor/)

**Find and redact PII and secrets in text of any size, in constant memory, entirely offline.**

SafeStream-Redactor streams a file through a fixed-size window, so a 100 GB log uses the
same memory as a 1 KB one. In one pass it catches personal data (emails, cards, SSNs,
phone numbers, IP addresses, names) *and* credentials (cloud keys, API tokens, JWTs,
private keys, unknown high-entropy secrets). Everything outside a redacted span,
line endings included, comes out byte for byte as it went in.

Use it as a command-line tool, a Python library, a local REST API, an MCP server for AI
agents, a CI secret gate, or a local web playground.

**[Try it in your browser →](https://mounishsenisetty.github.io/SafeStream-Redactor/)** The demo runs the real package in WebAssembly,
so nothing you paste leaves your machine.

[![The live demo: a service log with its PII and credentials redacted, findings ranked by severity](https://raw.githubusercontent.com/MounishSenisetty/SafeStream-Redactor/main/docs/images/demo-playground.png)](https://mounishsenisetty.github.io/SafeStream-Redactor/)

## 30-second quickstart

```bash
pip install safestream-redactor
```

```console
$ printf 'user=bob@corp.example ssn: 123-45-6789 key=AKIAIOSFODNN7EXAMPLE\n' | safestream redact - -o -
user=[REDACTED] ssn: [REDACTED] key=[REDACTED]
```

Python 3.10+ on Linux, macOS or Windows. The base install has no third-party runtime
dependencies.

## Why SafeStream

- **Constant memory.** Text is processed in chunks with an overlapping window, so an
  entity cut by a chunk boundary is still caught whole, and memory never grows with
  input size. A [test](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/tests/test_memory.py)
  redacts a generated 1 GB file with peak Python allocations under 16 MiB.
- **PII and secrets together.** Most PII tools focus on personal data. SafeStream
  also detects AWS, GitHub, Slack, Stripe, Google, OpenAI and Anthropic keys, JWTs,
  private-key blocks, credentials in URLs, and undocumented secrets by entropy.
- **Offline by design.** While it runs, outbound network connections are blocked in
  process (on Linux, optionally by the kernel). The REST API, MCP server and web UI bind to
  loopback only, and nothing ever logs the matched values.
- **Deterministic.** Single-core, multi-core and native (Rust) runs produce byte-identical
  output, and every redaction mode is a pure function of the value, so equal inputs always
  redact the same way.

## Choose your path

| I want to… | Use | Go to |
|---|---|---|
| Sanitize files, directories or pipes | CLI | [CLI](#user-content-cli) |
| Redact inside my own application | Python library | [Python](#user-content-python) |
| Call it from another language or a container | REST API | [REST API](#user-content-rest-api) |
| Give an AI agent a safe redaction tool | MCP server | [MCP server](#user-content-mcp-server) |
| Try it without installing anything | Live demo | [Open the demo](https://mounishsenisetty.github.io/SafeStream-Redactor/) |
| Try it on my own large files, without code | Local web playground | [Web playground](#user-content-web-playground) |
| Block secrets before they are committed or merged | Pre-commit hook, GitHub Action | [CI gate](#user-content-ci-gate) |
| Run it fully isolated | Docker | [Docker](#user-content-docker) |

## Quickstarts

The examples below use this small log. Every command and output in this README is run by
the test suite, so what you see is what you get.

```console
$ printf '%s\n' 'login ok user=maria.garcia@corpmail.com ip=10.20.30.40' 'payment card=4111 1111 1111 1111 ssn=123-45-6789' 'deploy aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz' > app.log
```

### CLI

```console
$ safestream redact app.log -o -
login ok user=[REDACTED] ip=[REDACTED]
payment card=[REDACTED] ssn=[REDACTED]
deploy aws_key=[REDACTED] token=[REDACTED]
$ safestream detect app.log
app.log:1:15: email  conf=0.95
app.log:1:44: ipv4  conf=1.00
app.log:2:14: credit_card  conf=1.00
app.log:2:38: ssn  conf=1.00
app.log:3:16: aws_key  conf=0.98
app.log:3:43: github_token  conf=0.98
-- 6 detection(s) (matched text hidden; --show-text reveals it)
$ safestream redact app.log -o - --types email,ssn --mode mask --keep-last 4
login ok user=*********************.com ip=10.20.30.40
payment card=4111 1111 1111 1111 ssn=*******6789
deploy aws_key=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghijklmnopqrstuvwxyz
```

`detect` never prints the matched values unless you pass `--show-text`, so its output is
safe to keep in logs. More things to try:

```bash
safestream redact app.log -o clean.log --mode pseudonymize --hmac-key "$KEY"  # stable <EMAIL_…> tokens
safestream redact logs/ -o logs_clean/ --workers 8         # a directory tree, in parallel
safestream redact huge.log -o clean.log --workers 8        # one big file, split across cores
tail -f app.log | safestream redact - -o -                 # a live stream
safestream redact app.log -o clean.log --stats --report run.json   # counts only, never values
safestream init-config -o policy.toml                       # a documented policy file to edit
```

Every option, redaction mode and exit code: [docs/CLI.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/CLI.md).

### Python

```python
from safestream_redactor import EntityType, RedactionPolicy, Redactor

redactor = Redactor()
redactor.redact("email bob@corp.io, ssn: 123-45-6789")  # -> 'email [REDACTED], ssn: [REDACTED]'

# detect without redacting; your code gets the matched text, logs never do
[(d.entity_type.value, d.text) for d in redactor.detect("mail bob@corp.io from 10.0.0.1")]
# -> [('email', 'bob@corp.io'), ('ipv4', '10.0.0.1')]

# choose the types, and how each one is rewritten
policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
Redactor(types=["email"], policy=policy).redact("bob@corp.io 123-45-6789")
# -> '<EMAIL> 123-45-6789'

# file to file in constant memory; the output appears atomically, never half-written
stats = redactor.redact_file("app.log", "app.clean.log")
stats.summary()  # -> '6 detection(s): aws_key=1, credit_card=1, email=1, github_token=1, ipv4=1, ssn=1'

# any iterable of text chunks: a file object, a socket reader, a generator
with open("app.log", newline="") as source:
    for piece in redactor.redact_stream(source):
        print(piece, end="")
```

### REST API

A standard-library HTTP server around the same engine. It binds to `127.0.0.1` and never
logs request bodies.

```bash
safestream serve            # http://127.0.0.1:8000
```

```bash
curl -s -X POST http://127.0.0.1:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'
# {"redacted": "email [REDACTED] key [REDACTED]", "total_detections": 2, "detections_by_type": {"aws_key": 1, "email": 1}}
```

`POST /scan` returns types and offsets only, never the matched text. There are also
`GET /health`, `/version` and `/detectors`. See [docs/rest-api.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/rest-api.md).

### MCP server

`safestream mcp-serve` gives an AI agent `scan`, `redact`, `explain_detection`,
`detectors` and `health` tools over stdio. Add it to your MCP client's configuration:

```json
{
  "mcpServers": {
    "safestream": { "command": "safestream", "args": ["mcp-serve"] }
  }
}
```

`scan` tells the agent *what* and *where*, never the secret itself. For
`deploy key AKIAIOSFODNN7EXAMPLE` it returns:

```json
{"count": 1, "findings": [{"type": "aws_key", "start": 11, "end": 31, "length": 20, "confidence": 0.98, "severity": "critical", "detector": "deterministic", "redacted": true}]}
```

See [docs/MCP.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/MCP.md).

### Web playground

The [live demo](https://mounishsenisetty.github.io/SafeStream-Redactor/) needs no install. It covers the playground, the streaming
inspector, and the REST and MCP consoles, for inputs up to 1 MiB. For big files, run the
playground locally:

```bash
pip install 'safestream-redactor[ui]'
safestream ui               # opens http://127.0.0.1:8501
```

Paste text or upload a file to see findings highlighted by severity, the original and
redacted text side by side, and a step-by-step replay of the streaming engine. It is
served on loopback only, with telemetry off and the network guard on.

![The web playground in Redact mode: original and redacted text side by side](https://raw.githubusercontent.com/MounishSenisetty/SafeStream-Redactor/main/docs/images/web-ui-redact.png)

See [docs/WEB_UI.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/WEB_UI.md).

### CI gate

`safestream detect PATHS --fail-on-detect` exits with status 1 when it finds anything. It
reports `file:line:col` and the type, never the secret. As a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MounishSenisetty/SafeStream-Redactor
    rev: v0.5.0
    hooks:
      - id: safestream-detect
```

As a GitHub Action, with an optional SARIF report for code scanning:

```yaml
- uses: MounishSenisetty/SafeStream-Redactor@v0.5.0
  with:
    paths: "."
    sarif-file: results.sarif
```

See [docs/CI_CD.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/CI_CD.md).

### Docker

Multi-architecture images (amd64, arm64) with an SBOM and provenance are published to
GitHub Container Registry. Run with no network at all:

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD":/data \
    ghcr.io/mounishsenisetty/safestream-redactor redact /data/app.log -o /data/clean.log
```

[`docker-compose.yml`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docker-compose.yml)
adds a read-only filesystem, no capabilities and a 64 MiB memory cap.

## Install options

| Install | Adds |
|---|---|
| `pip install safestream-redactor` | Everything above except the extras below. No runtime dependencies. |
| `pip install 'safestream-redactor[native]'` | The Rust core: 3–12× faster, byte-identical output. Prebuilt wheels for Linux (x86_64/aarch64, glibc and musl), macOS and Windows. Enable with `--backend native`. |
| `pip install 'safestream-redactor[ui]'` | The web playground (Streamlit). |
| `pip install 'safestream-redactor[crypto]'` | Reversible `--mode encrypt` (AES-256-GCM) and `safestream deanonymize`. |
| `pip install 'safestream-redactor[all]'` | `native`, `ui` and `crypto` together. |
| `pip install 'safestream-redactor[ner]'` | spaCy names, organisations and locations (`--ner`). Then run `python -m spacy download en_core_web_sm`. |
| `pip install 'safestream-redactor[onnx]'` | An on-device ONNX NER model you supply (`--onnx`); see [docs/DETECTORS.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/DETECTORS.md). |

Only need the command? `pipx install safestream-redactor`, or run it without installing:
`uvx safestream-redactor --help`.

## What it detects

| Category | Entity types |
|---|---|
| Personal data | `email`, `phone`, `credit_card`, `ssn`, `ipv4`, `ipv6`, `mac_address`, `address`, `dob`, `username` |
| Labelled identifiers | `id_number`: account, patient, MRN, passport, policy and case numbers after their label |
| Cloud and service credentials | `aws_key`, `aws_secret`, `aws_account_id`, `github_token`, `slack_token`, `slack_webhook`, `stripe_key`, `google_api_key`, `sendgrid_key`, `twilio_key`, `npm_token`, `openai_key`, `anthropic_key`, `vendor_token` |
| Other secrets | `api_key`, `jwt`, `private_key`, `url_credentials`, `password_hash`, `secret` (high entropy, no known format) |
| Names (with `[ner]` or `[onnx]`) | `person`, `org`, `loc` |
| Opt-in | `date` (`--dates`), `url` (`--types url`), regional IDs with `--regional`: `iban`, `crypto_address`, `uk_nino`, `nhs_number`, `in_aadhaar`, `in_pan` |
| Your own | `custom`, from `--custom-word` and `--custom-regex` |

Card, IBAN, NHS and Aadhaar numbers are checksum-validated. Matches identified by
shape alone (a bare SSN, phone number, email or IP) score lower next to words like
`example` or `test`, so documentation snippets are not redacted.

## How it works

```
 text chunks ──> [ rolling buffer: chunk + 8 KiB overlap ] ──> redacted chunks
                                   │
          ┌────────────────────────┼─────────────────────────┐
          ▼                        ▼                         ▼
   patterns + validators     entropy scoring          NER (optional)
   (Luhn, SSN rules, …)      for unknown secrets      spaCy or ONNX
          └────────────────────────┼─────────────────────────┘
                                   ▼
            contextual scoring ─> confidence filter ─> overlap resolution
                                   ▼
        redaction policy: replace, mask, pseudonymize, hash, encrypt, fictionalize
```

Only text at least one overlap (8 KiB by default) from the end of the buffer is written
each round. The rest is carried into the next round, so an entity up to that length is
always seen whole, even when a chunk boundary cuts through it. If an output boundary would
split a detection, it moves back to the detection's start. Architecture details:
[SYSTEM_DESIGN.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/SYSTEM_DESIGN.md).

## Performance and accuracy

- **Throughput:** about 1.1–1.4 MB/s per core in pure Python and 3–17 MB/s with the native
  core, on the evaluation corpora in power-saving mode on one thread. `--workers N` scales
  across cores.
- **Against Presidio's pattern recognizers:** higher precision on every corpus and 24–169×
  faster per core. Character F1 is higher on secrets and RedactionBench, level on
  presidio-research, and lower on ai4privacy with default settings.
- **Where it loses:** Presidio's transformer engine redacts more entities fully, and wins on
  ai4privacy. SafeStream misses values inside structured fields, unlabelled ID numbers, many
  international phone formats, and many names.

Full tables, confidence intervals and conditions: [docs/EVALUATION.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/EVALUATION.md).

## Limitations

No tool can guarantee every name or free-form identifier in prose is found: "April" is a
name and a month, and an account number looks like any other run of digits. SafeStream is
tuned for high precision on structured PII and credentials. For names, enable `[ner]` or
`[onnx]`. For identifiers without a fixed format, add label-anchored patterns, as in
[`examples/policy.toml`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/examples/policy.toml).
Review redacted output before sharing it anywhere a miss would be costly.

## Security

The in-process network guard is defence in depth, not a sandbox: native code or a child
process can bypass it. On Linux, `--offline-hard seccomp` or `--offline-hard netns` adds a
kernel-enforced block, and `docker run --network none` isolates the whole container. The
threat model and how to report a vulnerability are in
[SECURITY.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/SECURITY.md).

## Documentation

| Topic | Page |
|---|---|
| Every CLI option, policy files, plugins, network isolation | [docs/CLI.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/CLI.md) |
| Detection tiers and how to extend them | [docs/DETECTORS.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/DETECTORS.md) |
| A guided tour of every feature | [docs/DEMO.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/DEMO.md) |
| Memory budgets and constant-memory guarantees | [docs/MEMORY_ARCHITECTURE.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/MEMORY_ARCHITECTURE.md) |
| The native core | [docs/NATIVE_CORE.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/NATIVE_CORE.md) |
| Linux file-system DLP (`safestream fanotify`) | [docs/FANOTIFY.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/FANOTIFY.md) |
| Evaluation results | [docs/EVALUATION.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/EVALUATION.md) |
| Changelog | [CHANGELOG.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/CHANGELOG.md) |

## Contributing

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
pip install -e '.[dev]'
pytest
```

See [CONTRIBUTING.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/CONTRIBUTING.md)
and the [good first issues](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/good_first_issues.md).

## License

[MIT](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/LICENSE)
