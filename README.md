# SafeStream-Redactor

[![CI](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safestream-redactor)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor)](https://pypi.org/project/safestream-redactor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

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

## Install

Three ways — pip, from source, or Docker:

```bash
# 1. pip (constant-memory core, zero third-party runtime deps)
pip install safestream-redactor

# optional spaCy-based PERSON/ORG/LOC detection:
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm
```

```bash
# 2. from a clone (for development or the latest main)
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
pip install -e '.[dev]'
```

```bash
# 3. Docker — nothing to install locally; mount a directory and go
docker build -t safestream-redactor .
docker run --rm -v "$PWD":/data safestream-redactor \
    redact /data/input.txt -o /data/output.txt
```

## Quickstart

### CLI

```bash
# redact everything detectable, write to out.txt
safestream redact input.txt -o out.txt

# only emails + SSNs, custom replacement, plus a custom codename
safestream redact input.txt -o out.txt --types email,ssn --replace "***" --custom-word "ProjectX"

# mask all but the last 4 characters
safestream redact cards.csv -o masked.csv --mode mask --keep-last 4

# deterministic pseudonyms (same input -> same token), streaming from stdin
tail -f app.log | safestream redact - -o - --mode pseudonymize --hmac-key "$SECRET"

# just list what would be redacted
safestream detect input.txt --json
```

### Python API

```python
from safestream_redactor import Redactor, RedactionPolicy, EntityType

redactor = Redactor()
redactor.redact("email bob@corp.io, ssn: 123-45-6789")
# 'email [REDACTED], ssn: [REDACTED]'

# detection only
for d in redactor.detect("card 4111 1111 1111 1111"):
    print(d.entity_type, d.confidence, d.text)

# per-type replacements
policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
Redactor(policy=policy).redact("write to bob@corp.io")   # 'write to <EMAIL>'

# constant-memory file-to-file
Redactor().redact_file("huge.log", "huge_redacted.log")

# generator-based streaming (any iterable of text chunks)
with open("huge.log") as f:
    for clean_chunk in Redactor().redact_stream(iter(lambda: f.read(65536), "")):
        process(clean_chunk)
```

### Policy files (TOML)

```toml
# policy.toml
[detection]
types = ["email", "ssn", "credit_card"]

[redaction]
mode = "replace"
replacement = "[GONE]"

[redaction.replacements]
email = "<EMAIL>"

[custom]
words = ["ProjectX"]
```

```bash
safestream redact input.txt -o out.txt --config policy.toml
```

## Architecture

```
 chunks ──> [ rolling buffer + overlap window ] ──> redacted chunks
                     │
                     ▼
        ┌───────────────────────────┐
        │ Tier 1  deterministic     │  regex + validators (Luhn, SSN rules,
        │                           │  ipaddress parsing, ...) + credentials
        ├───────────────────────────┤
        │ Tier 2  statistical       │  Shannon-entropy scoring for bespoke,
        │                           │  undocumented high-entropy secrets
        ├───────────────────────────┤
        │ Tier 3  NER (optional)    │  spaCy PERSON / ORG / LOC
        ├───────────────────────────┤
        │ Tier 4  contextual        │  trigger words boost/suppress
        │                           │  confidence ("ssn:", "example", ...)
        └───────────────────────────┘
                     │
          confidence filter + overlap resolution
                     │
                     ▼
          redaction policy (replace / mask / pseudonymize / per-type)
```

The streaming engine keeps a rolling buffer of `chunk_size + overlap` characters. Only text
at least `overlap` characters from the buffer's end is emitted each round; the tail is carried
into the next round so any entity up to `overlap` characters long (default 4 KB) is always
seen whole at least once, even when a chunk boundary cuts straight through it. An emit
boundary that would split a detection retreats to the detection's start. Already-emitted
text is kept (up to `overlap` chars) as read-only left context so the contextual tier scores
identically to whole-text mode.

Detected entity types:

- **PII:** `email`, `phone`, `credit_card` (Luhn-validated), `ssn`, `ipv4`, `ipv6`, plus
  `person` / `org` / `loc` with the NER extra.
- **Credentials & secrets:** `aws_key`, `github_token`, `slack_token`, `slack_webhook`,
  `stripe_key`, `google_api_key`, `sendgrid_key`, `twilio_key`, `npm_token`, `jwt`,
  `private_key`, `api_key` (generic `key = value` assignments), and `secret`
  (undocumented high-entropy strings, on by default — disable with `--no-entropy`).
- `custom` for user-supplied words and regexes.

## Comparison

**Structured PII** — 5.2 MB synthetic corpus, span-overlap + type-aware scoring
(reproduce with `benchmarks/generate_dataset.py` then `benchmarks/run_benchmark.py`):

| Tool                          | Precision | Recall | F1    | Constant memory |
| ----------------------------- | --------- | ------ | ----- | --------------- |
| safestream-redactor           | 1.000     | 1.000  | 1.000 | ✅              |
| Microsoft Presidio (patterns) | 0.928     | 0.815  | 0.868 | ❌              |

> Honest caveats: the corpus is generated from standard entity formats, which favours any
> regex-based detector — read SafeStream's perfect score as *"handles standard PII cleanly"*,
> not a blanket win. Presidio was run via its own pattern recognizers (its spaCy NER tier is a
> separate, model-dependent path). On free-form prose with names/locations, Presidio's NER
> will out-recall SafeStream's regex core unless you enable the `[ner]` extra.

**Credentials & secrets** — where the tools genuinely diverge. On a corpus of AWS keys,
GitHub/Slack/Stripe/Google/SendGrid/npm tokens, JWTs, and a random high-entropy secret:

| Tool                | Credentials detected |
| ------------------- | -------------------- |
| safestream-redactor | 9 / 9                |
| Microsoft Presidio  | 0 / 9                |

Presidio ships no recognizers for these; credential/secret detection is SafeStream's
core differentiator, alongside constant-memory streaming.

## Development

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
pip install -e '.[dev]'
pytest                                   # fast suite
SAFESTREAM_MEMTEST_MB=100 pytest -m memory -o addopts=''   # constant-memory proof
ruff check . && ruff format --check .       # lint + format
mypy                                        # strict type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues live in
[docs/good_first_issues.md](docs/good_first_issues.md) and the issue tracker.

## License

[MIT](LICENSE)
