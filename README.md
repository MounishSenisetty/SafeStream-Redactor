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

# redact a whole directory tree in parallel (RAM/CPU-aware worker count)
safestream redact ./logs -o ./logs_redacted --workers 8

# just list what would be redacted
safestream detect input.txt --json
```

While redacting, the CLI installs an **offline network guard** by default: any attempt to
open a non-loopback connection raises an error, so sensitive text provably never leaves the
machine. Pass `--allow-network` to disable it.

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

# parallel, RAM-aware redaction across a directory tree
from safestream_redactor.scheduler import redact_tree
redact_tree("logs/", "logs_redacted/", Redactor(), workers=8)

# enforce the offline guarantee around any block of code
from safestream_redactor import netguard
with netguard.enforced():
    Redactor().redact_file("huge.log", "huge_redacted.log")   # network calls now raise
```

### Extending with plugins

Any installed package can add a detection tier by advertising an entry point — no fork
required. SafeStream discovers and loads them automatically.

```toml
# in your plugin package's pyproject.toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_pkg.detectors:MyDetector"   # a Detector instance or zero-arg factory
```

A detector is anything with a `name` and `detect(text) -> list[Detection]` (the
`Detector` protocol). Disable plugin loading with `Redactor(load_plugins=False)`.

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

  Scheduler: RAM/CPU-aware multiprocessing across files (safestream/scheduler.py).
  Offline guard: any non-loopback connection raises NetworkAccessError (netguard.py).
  Plugins: third-party tiers load from the 'safestream_redactor.detectors' entry point.
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

**Realistic / adversarial** — 1 MB of noisy log / JSON / CSV / SQL records dense with
*hard negatives* (order numbers, ISO timestamps, UUIDs, git hashes, invalid-area SSNs,
5-octet version strings) that tempt false positives — both tools face the same distractors
(reproduce with `benchmarks/generate_hard_dataset.py`):

| Tool                          | Precision | Recall | F1    | Throughput  |
| ----------------------------- | --------- | ------ | ----- | ----------- |
| safestream-redactor           | 0.999     | 1.000  | 1.000 | 3.13 MB/s   |
| Microsoft Presidio (patterns) | 0.649     | 0.843  | 0.734 | 0.06 MB/s   |

This is the meaningful test: SafeStream holds 0.999 precision under the distractors while
Presidio's phone recognizer emits thousands of false positives (P=0.649).

> Honest caveats: the gold entities still use standard formats SafeStream targets, so treat
> these as a strong-but-not-final signal, not an independent audit. Presidio was run via its
> own pattern recognizers (its spaCy NER tier is a separate, model-dependent path). On
> free-form prose with names/locations, Presidio's NER will out-recall SafeStream's regex
> core unless you enable the `[ner]` extra.

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
