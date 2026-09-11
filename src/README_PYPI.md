# SafeStream-Redactor

[![PyPI](https://img.shields.io/pypi/v/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![License](https://img.shields.io/pypi/l/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)

Streaming PII & credential redaction for massive text files — constant **O(1) memory**,
multi-tier detection (regex + validators + entropy + optional NER + contextual heuristics),
fully customizable redaction.

Redact a 100 GB log file with the same memory footprint as a 1 KB one.

Unlike general PII engines (Presidio, scrubadub) it also detects **credentials and
secrets** — AWS keys, GitHub/Slack/Stripe/Google/SendGrid/Twilio/npm tokens, JWTs,
private-key blocks, and *undocumented* high-entropy secrets — in the same streaming pass.

## Why?

Most PII tools load the whole document into memory. SafeStream-Redactor processes text in
fixed-size chunks with an overlapping context window, so entities that straddle chunk
boundaries are still caught — and memory use never grows with file size (proven by a test
that redacts a generated 1 GB file under a 16 MB allocation cap).

## Features

- **Constant-memory streaming** — process very large files without loading them into memory.
- **Multi-tier detection** — deterministic patterns + validators, entropy analysis,
  optional spaCy NER, and contextual scoring.
- **PII** — emails, phone numbers, credit cards, SSNs, IPv4/IPv6, and optional
  names/organizations/locations.
- **Credentials & secrets** — API keys, cloud credentials, service tokens, JWTs, private
  keys, and generic high-entropy secrets.
- **Redaction modes** — replace, mask, deterministic pseudonymize, and per-type replacements.
- **Parallel processing** — directory trees, or a single large file split across workers
  (output byte-identical to the sequential pass).
- **Offline network guard** — blocks non-loopback network access by default during CLI redaction.
- **Extensible** — add custom detection tiers via Python entry points.
- **Configurable policies** — define detection and redaction behavior in TOML.

## Install

```bash
pip install safestream-redactor

# optional spaCy-based PERSON/ORG/LOC detection:
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm

# optional native (Rust) accelerator for the deterministic tier
# (byte-identical; use Redactor(backend="native"), falls back to Python if absent):
pip install 'safestream-redactor[native]'
```

Docker:

```bash
docker run --rm -v "$PWD":/data ghcr.io/mounishsenisetty/safestream-redactor \
    redact /data/input.txt -o /data/output.txt
```

## Quickstart

### CLI

```bash
# redact everything detectable
safestream redact input.txt -o out.txt

# only emails + SSNs, custom replacement
safestream redact input.txt -o out.txt --types email,ssn --replace "***"

# mask all but the last 4 characters
safestream redact cards.csv -o masked.csv --mode mask --keep-last 4

# stream from stdin to stdout
cat input.log | safestream redact - -o -

# CI / pre-commit secret gate: non-zero exit if anything is found
safestream detect build.log --fail-on-detect

# generate a documented, validated starter policy
safestream init-config -o policy.toml
```

While redacting, the CLI installs a best-effort **offline network guard** by default
(pass `--allow-network` to disable it).

### Python API

```python
from safestream_redactor import Redactor, RedactionPolicy, EntityType

redactor = Redactor()
redactor.redact("email bob@corp.io, ssn: 123-45-6789")
# 'email [REDACTED], ssn: [REDACTED]'

# per-type replacements
policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
Redactor(policy=policy).redact("write to bob@corp.io")   # 'write to <EMAIL>'

# constant-memory file-to-file; the write is atomic, and the returned stats
# carry per-type counts (content-free audit evidence)
stats = Redactor().redact_file("huge.log", "huge_redacted.log")
print(stats.summary())   # '3 detection(s): email=2, ssn=1'

# split one large file across cores; byte-identical to the sequential pass
Redactor().redact_file("huge.log", "huge_redacted.log", workers=8)
```

### REST API

An optional, standard-library-only REST server wraps the same `Redactor` (no extra
dependency, loopback-only by default, request bodies never logged):

```bash
safestream serve                       # http://127.0.0.1:8000
curl -s -X POST http://127.0.0.1:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'
# {"redacted": "email [REDACTED] key [REDACTED]", "total_detections": 2, ...}
```

Endpoints: `GET /health`, `GET /version`, `GET /detectors`, `POST /redact`, `POST /scan`.

## Detection accuracy & limitations

SafeStream is tuned to favour **precision** on structured PII and credentials. Free-form
names and addresses need the optional NER tier (`[ner]` extra); without it they are not
detected. 100% recall and precision together are not achievable for free-text PII by any
tool — treat this as high-recall for credentials and structured PII, and best-effort for
free prose.

## Documentation

Full documentation — architecture diagrams (Mermaid & PlantUML), REST API reference,
security model, benchmarks, and the research/comparison material — lives in the GitHub
project:

**https://github.com/MounishSenisetty/SafeStream-Redactor**

## License

MIT.
