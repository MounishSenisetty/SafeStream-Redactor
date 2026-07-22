# SafeStream-Redactor

[![CI](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safestream-redactor)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor)](https://pypi.org/project/safestream-redactor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Streaming PII & credential redaction for massive text files — constant **O(1) memory**,
multi-tier detection (regex + NER + contextual heuristics), fully customizable redaction.

Redact a 100 GB log file with the same memory footprint as a 1 KB one.

## Why?

Most PII tools load the whole document into memory. SafeStream-Redactor processes text in
fixed-size chunks with an overlapping context window, so entities that straddle chunk
boundaries are still caught — and memory use never grows with file size (proven by a test
that redacts a generated 1 GB file under a 16 MB allocation cap).

## Install

```bash
pip install safestream-redactor

# optional spaCy-based PERSON/ORG/LOC detection:
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm
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
        │                           │  ipaddress parsing, ...)
        ├───────────────────────────┤
        │ Tier 2  NER (optional)    │  spaCy PERSON / ORG / LOC
        ├───────────────────────────┤
        │ Tier 3  contextual        │  trigger words boost/suppress
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

Detected entity types: `email`, `phone`, `credit_card` (Luhn-validated), `ssn`, `ipv4`,
`ipv6`, `aws_key`, `github_token`, `api_key`, `jwt`, `private_key`, plus `person` / `org` /
`loc` with the NER extra and `custom` for user-supplied words and regexes.

## Comparison

Benchmarks on the synthetic labeled dataset in [`benchmarks/`](benchmarks/) (run them
yourself — see [benchmarks/README.md](benchmarks/README.md)):

| Tool                | Precision | Recall | F1  | Throughput | Constant memory |
| ------------------- | --------- | ------ | --- | ---------- | --------------- |
| safestream-redactor | TBD       | TBD    | TBD | TBD        | ✅              |
| Microsoft Presidio  | TBD       | TBD    | TBD | TBD        | ❌              |
| scrubadub           | TBD       | TBD    | TBD | TBD        | ❌              |

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
