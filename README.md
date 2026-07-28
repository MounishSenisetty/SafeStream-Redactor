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

# released multi-arch images (amd64/arm64, with SBOM + provenance) are on GHCR:
docker run --rm -v "$PWD":/data ghcr.io/mounishsenisetty/safestream-redactor \
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

# CI / pre-commit secret gate: non-zero exit if anything is found
safestream detect build.log --fail-on-detect

# per-type counts to stderr, plus a JSON run report for compliance filing
# (the report contains only type names, counts, and sizes — never matched text)
safestream redact input.txt -o out.txt --stats --report run.json

# non-UTF-8 source? decode it correctly (undecodable bytes are otherwise
# reported and warned about, since unscanned bytes are a coverage risk)
safestream redact legacy.log -o out.log --encoding latin-1

# generate a documented, validated starter policy to customise
safestream init-config -o policy.toml
```

While redacting, the CLI installs an **offline network guard** by default: any attempt to
open a non-loopback connection through Python's socket layer raises an error. This is
best-effort, defense-in-depth egress prevention for this process, its plugins, and its
Python dependencies — **not** a hard boundary: native extensions issuing raw syscalls, a
spawned subprocess, or another process on the machine are outside its reach. For a
guaranteed boundary, also run with no network (`docker run --network none ...`) or a
network namespace / seccomp policy. Pass `--allow-network` to disable the guard. See
[SECURITY.md](SECURITY.md) for the full threat model.

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

# constant-memory file-to-file; the write is atomic (never a partial output)
# and the returned stats carry per-type counts — content-free audit evidence
stats = Redactor().redact_file("huge.log", "huge_redacted.log")
print(stats.summary())   # '3 detection(s): email=2, ssn=1'

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

Each tier-1 pattern declares literal *anchors* every match must contain (`AKIA`, `eyJ`,
`@`, `://`, a digit, …); a cheap substring scan per window skips regexes that cannot
match, so secret-sparse text runs ~25× faster with provably identical output (a
differential test compares prefiltered and unfiltered detection).

The streaming engine keeps a rolling buffer of `chunk_size + overlap` characters. Only text
at least `overlap` characters from the buffer's end is emitted each round; the tail is carried
into the next round so any entity up to `overlap` characters long is always seen whole at
least once, even when a chunk boundary cuts straight through it. An emit boundary that would
split a detection retreats to the detection's start. Already-emitted text is kept (up to
`overlap` chars) as read-only left context so the contextual tier scores identically to
whole-text mode.

**Guarantee and its limit.** The default overlap (16 KB) is deliberately larger than the
biggest entity any built-in detector can produce (a private-key block is bounded to ~8 KB),
so every built-in entity is caught across chunk boundaries. An entity *longer* than `overlap`
— only possible from an unbounded custom regex or an unusually long high-entropy token — can
be split and missed in streaming mode; SafeStream warns when it constructs a redactor with an
undersized overlap and again if it ever detects an oversized entity, so raise `overlap` if you
work with entities larger than 16 KB.

Detected entity types:

- **PII:** `email`, `phone`, `credit_card` (Luhn-validated), `ssn`, `ipv4`, `ipv6`, plus
  `person` / `org` / `loc` with the NER extra.
- **Credentials & secrets:** `aws_key`, `github_token`, `slack_token`, `slack_webhook`,
  `stripe_key`, `google_api_key`, `sendgrid_key`, `twilio_key`, `npm_token`,
  `openai_key`, `anthropic_key`, `jwt`, `private_key`,
  `url_credentials` (passwords embedded in connection strings — only the password is
  redacted, so `postgres://svc:hunter2@db/app` becomes `postgres://svc:[REDACTED]@db/app`),
  `api_key` (generic `key = value` assignments), and `secret`
  (undocumented high-entropy strings, on by default — disable with `--no-entropy`).
- `custom` for user-supplied words and regexes.

## Evaluation

> **Read this before quoting any number below.** The corpora these numbers come from
> are *synthetic and self-generated*: the gold positives are emitted in the same
> canonical formats the detector targets, so a near-perfect score on them measures
> **format coverage and false-positive resistance, not real-world recall**. They are a
> regression fixture, not an accuracy claim, and a self-generated benchmark is not
> evidence of accuracy on your data. For a defensible accuracy number, run
> `benchmarks/evaluate.py` against an independent labeled corpus you control (see
> [benchmarks/README.md](benchmarks/README.md) — the Presidio research dataset, CoNLL,
> and the n2c2 de-identification set are the recommended targets). Expect recall on
> free-form prose (names, addresses) to be substantially lower than on structured PII
> unless the `[ner]` extra is enabled.

**Format coverage & false-positive resistance (synthetic).** On the adversarial corpus
(1 MB of noisy log/JSON/CSV/SQL dense with hard negatives — order numbers, ISO
timestamps, UUIDs, git hashes, invalid-area SSNs, 5-octet version strings; reproduce
with `benchmarks/generate_hard_dataset.py` then `benchmarks/run_benchmark.py`):

| Tool                          | Precision | Recall\* | Throughput  |
| ----------------------------- | --------- | -------- | ----------- |
| safestream-redactor           | 0.999     | 1.000    | ~3.1 MB/s   |
| Microsoft Presidio (patterns) | 0.649     | 0.843    | ~0.06 MB/s  |

\* Recall here is against self-generated positives and is *not* a real-world recall
figure — see the note above. The meaningful, non-circular result in this table is
**precision under distractors**: SafeStream holds 0.999 while Presidio's phone
recognizer emits thousands of false positives (P=0.649). Presidio was run via its
pattern recognizers; its spaCy NER tier is a separate, model-dependent path that will
out-recall SafeStream's regex core on prose unless you enable `[ner]`.

**Throughput is a known limitation, not a strength.** ~3 MB/s single-core means a
100 GB file takes hours; compiled scanners (gitleaks, ripgrep-class) are 100–1000×
faster. The value here is constant memory and credential coverage, not raw speed —
closing the speed gap (Vectorscan/re2 backend, intra-file parallelism) is on the
[roadmap](docs/ROADMAP.md).

**Credentials & secrets** — the genuinely differentiating capability. On a corpus of
AWS keys, GitHub/Slack/Stripe/Google/SendGrid/npm tokens, JWTs, and a random
high-entropy secret, Presidio ships no recognizers and detects 0/9; SafeStream detects
9/9. This is a capability difference (Presidio has no credential recognizers at all),
not a tuned accuracy comparison.

## Development

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
pip install -e '.[dev]'
pytest                                   # fast suite (incl. property-based tests)
pytest --cov=safestream_redactor         # with the 95% coverage gate
SAFESTREAM_MEMTEST_MB=100 pytest -m memory -o addopts=''   # constant-memory proof
ruff check . && ruff format --check .       # lint + format
mypy                                        # strict type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues live in
[docs/good_first_issues.md](docs/good_first_issues.md) and the issue tracker.
The audited state of the codebase and the phased improvement plan are in
[docs/AUDIT.md](docs/AUDIT.md) and [docs/ROADMAP.md](docs/ROADMAP.md); the security
policy and threat model (what the offline guard does and does not cover) are in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
