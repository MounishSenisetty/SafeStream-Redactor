# SafeStream-Redactor — Demo Guide

A single, guided demo of SafeStream-Redactor across **all four ways to run it** —
PyPI install, git clone, Docker, and the REST API — plus a full feature tour,
dataset generation, and the benchmark suite. Every command below is copy-paste
runnable, and the output shown was captured from an actual run.

> **What it does, in one line:** streaming PII **and** credential/secret detection &
> redaction for text of any size, at **constant O(1) memory** — redact a 100 GB log
> with the same footprint as a 1 KB one.

---

## 0. Fastest path — one command

From a clone (or anywhere the package is installed), run the bundled demo. It
generates a tiny sample containing one of every major entity type and walks the
entire feature surface — detect, all redaction modes, custom patterns, TOML
policy, streaming, run reports, and the CI secret-gate — in one shot. No network,
no download, no real secrets.

```bash
examples/run_demo.sh            # the fast feature tour
examples/run_demo.sh --bench    # also generate a 1 MB corpus and run the benchmark
```

**File to use:** [`examples/run_demo.sh`](../examples/run_demo.sh). The rest of this
guide breaks the same features out by install method and shows each command
individually.

### Which file / command for each of the four methods

| Method | Get it | Entry point | Key files |
|---|---|---|---|
| **PyPI** | `pip install safestream-redactor` | `safestream` CLI + `import safestream_redactor` | [`src/README_PYPI.md`](../src/README_PYPI.md) |
| **Clone (dev)** | `pip install -e '.[dev]'` | `safestream`, `pytest`, `benchmarks/*.py` | [`pyproject.toml`](../pyproject.toml), [`tests/`](../tests), [`benchmarks/`](../benchmarks) |
| **Docker** | `docker build -t safestream-redactor .` or pull GHCR | `docker run … safestream …` | [`Dockerfile`](../Dockerfile) |
| **REST API** | `safestream serve` | `http://127.0.0.1:8000` | [`src/safestream_redactor/api.py`](../src/safestream_redactor/api.py), [`docs/rest-api.md`](rest-api.md) |

---

## The demo sample

Everything below redacts this small sample (the one `examples/run_demo.sh`
generates). Save it as `sample.txt` if you want to follow along by hand — all
values are canonical **fake/example** constants:

```text
Customer Maria Garcia <maria.garcia@corpmail.com> called from +1 415 555 0132.
Card on file 4111 1111 1111 1111, SSN 123-45-6789, last login from 10.20.30.40 (v6 2001:db8::8a2e:370:7334).
Deploy creds: AWS AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz, Slack xoxb-1234-5678-abcdefghijklmnop, Stripe sk_live_1234567890abcdefghijklmnop.
Session jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
Internal ref ProjectFalcon, employee EMP-40921.
NOTE: this is a test example value: 123-45-0000 should be suppressed by context.
```

---

## Method 1 — PyPI install

Nothing to build; install the published wheel (zero third-party runtime deps —
the core is standard-library only).

```bash
pip install safestream-redactor

# optional: spaCy NER tier for free-form PERSON / ORG / LOC
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm
```

### CLI

```bash
safestream --version
safestream detect sample.txt --json          # list detections, redact nothing
safestream redact sample.txt -o out.txt      # redact everything detectable
safestream init-config -o policy.toml        # write a documented starter policy
```

### Python library

The library is the same engine the CLI and API call — identical results:

```python
from safestream_redactor import Redactor, RedactionPolicy, EntityType

Redactor().redact("email bob@corp.io, ssn: 123-45-6789")
# -> 'email [REDACTED], ssn: [REDACTED]'

# per-type replacement
policy = RedactionPolicy(replacements={EntityType.EMAIL: "<EMAIL>"})
Redactor(policy=policy).redact("write to bob@corp.io")
# -> 'write to <EMAIL>'

# constant-memory file-to-file (atomic write); returns content-free stats
stats = Redactor().redact_file("huge.log", "huge_redacted.log")
print(stats.summary())          # e.g. '3 detection(s): email=2, ssn=1'

# split one large file across cores; byte-identical to the sequential pass
Redactor().redact_file("huge.log", "huge_redacted.log", workers=8)
```

Public API: `Redactor`, `RedactionPolicy`, `RedactionMode`, `EntityType`,
`Detection`, `RedactionStats`, `Calibrator` — see
[`src/README_PYPI.md`](../src/README_PYPI.md).

---

## Method 2 — git clone (development)

Use this to run the tests, the benchmark suite, and the latest `main`.

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor.git
cd SafeStream-Redactor
pip install -e '.[dev]'          # editable install + pytest/ruff/mypy/hypothesis
```

Run the checks:

```bash
pytest                                   # unit + property tests (fast)
pytest -m memory -o addopts=''           # the constant-memory proof: 1 GB under a 16 MB cap
ruff check . && mypy src                 # lint + strict types
```

**Files to use:** [`pyproject.toml`](../pyproject.toml) (all deps and tooling live
here — there is no `setup.py` or `requirements.txt`), [`tests/`](../tests),
[`benchmarks/`](../benchmarks), and [`examples/policy.toml`](../examples/policy.toml).
The one-command demo (`examples/run_demo.sh`) works from a clone too.

---

## Method 3 — Docker

The image installs only the constant-memory core, so it stays small and runs
fully offline. There is no `docker-compose.yml`; one `Dockerfile` covers both
one-shot redaction and the API.

```bash
# build locally …
docker build -t safestream-redactor .

# … or pull the released multi-arch image (amd64/arm64, with SBOM + provenance)
docker pull ghcr.io/mounishsenisetty/safestream-redactor
```

**One-shot redaction** — mount a directory as `/data` and redact a file in place:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/data safestream-redactor \
    redact /data/sample.txt -o /data/out.txt
```

**Run the REST API in a container** — bind `0.0.0.0` *inside* the container but map
it only to the host's loopback so it never becomes internet-facing:

```bash
docker run --rm -p 127.0.0.1:8000:8000 safestream-redactor \
    serve --host 0.0.0.0 --port 8000
```

**File to use:** [`Dockerfile`](../Dockerfile) (multi-stage build; runs as an
unprivileged `safestream` user; `ENTRYPOINT` is the `safestream` CLI, `WORKDIR`
is `/data`).

---

## Method 4 — REST API

An **optional** local REST server wraps the same `Redactor`. It uses only the
Python standard library (`http.server`) — no extra dependency — binds to
`127.0.0.1` by default, never logs request bodies, and caps bodies at 8 MiB.

```bash
safestream serve                 # http://127.0.0.1:8000
```

Every endpoint, with real responses:

```bash
curl -s http://127.0.0.1:8000/health
# {"status": "ok"}

curl -s http://127.0.0.1:8000/version
# {"tool": "safestream-redactor", "version": "0.3.0"}

curl -s http://127.0.0.1:8000/detectors
# {"tiers": ["deterministic", "entropy", "contextual"], "entity_types": ["email", ...]}

curl -s -X POST http://127.0.0.1:8000/redact -H 'Content-Type: application/json' \
  -d '{"text":"email bob@corp.io key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789"}'
# {"redacted": "email [REDACTED] key [REDACTED] ssn [REDACTED]",
#  "total_detections": 3, "detections_by_type": {"aws_key": 1, "email": 1, "ssn": 1}}

curl -s -X POST http://127.0.0.1:8000/scan -H 'Content-Type: application/json' \
  -d '{"text":"email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'
# content-free — offsets + types only, never the matched substring:
# {"total_detections": 2, "detections_by_type": {"aws_key": 1, "email": 1},
#  "detections": [{"start": 6, "end": 17, "entity_type": "email", ...}, ...]}
```

**Files to use:** [`src/safestream_redactor/api.py`](../src/safestream_redactor/api.py)
and the full reference in [`docs/rest-api.md`](rest-api.md). `/scan` stays
content-free by design, so it is safe to log or store its responses.

---

## Feature tour

These are the steps `examples/run_demo.sh` runs, one flag at a time, against the
sample above. They work identically from the CLI, the library, the API, or Docker.

### Detect everything (redacts nothing)

```bash
safestream detect sample.txt --json
```
```json
{"type": "email", "start": 23, "end": 48, "text": "maria.garcia@corpmail.com", "confidence": 0.95, "source": "deterministic"}
{"type": "credit_card", "start": 92, "end": 111, "text": "4111 1111 1111 1111", "confidence": 1.0, "source": "deterministic"}
{"type": "aws_key", "start": 206, "end": 226, "text": "AKIAIOSFODNN7EXAMPLE", "confidence": 0.58, "source": "deterministic"}
{"type": "secret", "start": 331, "end": 362, "text": "xoxb-1234-5678-abcdefghijklmnop", "confidence": 0.6, "source": "entropy"}
… (email, phone, credit_card, ssn, ipv4, ipv6, aws_key, github_token, secret, stripe_key, jwt)
```

Note the Slack token is caught by the **entropy** tier (`source: entropy`) even
though it is not a hard-coded pattern — that is the undocumented-secret detector.

### Redaction modes

```bash
# default: replace with [REDACTED]
safestream redact sample.txt -o - 

# mask: keep the last 4 characters visible
safestream redact sample.txt -o - --mode mask --keep-last 4
#   Card on file ***************1111, SSN *******6789 …

# pseudonymize: deterministic keyed tokens (same input -> same token)
safestream redact sample.txt -o - --mode pseudonymize --hmac-key demo-key
#   <EMAIL_36f64ed61bd08e8a> … <SSN_39d12ae6849aa1eb> …
```

### Type filtering + per-type replacements

```bash
safestream redact sample.txt -o - --types email,ssn \
    --replace-type "email=<EMAIL>" --replace-type "ssn=<SSN>"
#   … <<EMAIL>> … SSN <SSN> … (everything else left untouched)
```

### Custom words and regexes

```bash
safestream redact sample.txt -o - --custom-word ProjectFalcon --custom-regex 'EMP-[0-9]+'
#   … Internal ref [REDACTED], employee [REDACTED].
```

### TOML policy files

Drive detection **and** redaction from a config file so behavior is reproducible
and reviewable. CLI flags override it; unknown keys are a hard error (fail-closed).

```bash
safestream redact sample.txt -o - --config examples/policy.toml
```

[`examples/policy.toml`](../examples/policy.toml) is a fuller, ready-to-use policy
that additionally **enables the NER tier** (`use_ner = true`) and ships custom
patterns (passport, driver's licence, bank account, employee ID, DOB). Because NER
needs the optional `[ner]` extra, install it first — or set `use_ner = false` /
use your own policy for a core-only run (that is what `run_demo.sh` does):

```bash
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm
safestream redact sample.txt -o - --config examples/policy.toml --ner
```

Generate a minimal starter policy to customize:

```bash
safestream init-config -o policy.toml
```

### Streaming through a pipe

```bash
cat sample.txt | safestream redact - -o -        # stdin '-' to stdout '-'
```

### Parallelism (directory trees or one large file)

```bash
# RAM/CPU-aware fan-out across a directory tree
safestream redact ./logs -o ./logs_redacted --workers 8

# split ONE big file across cores — output is byte-identical to the single-core pass
safestream redact huge.log -o clean.log --workers 8
```

### Stats + content-free run report

The report contains only type names, counts, and sizes — **never** matched text —
so it is safe to file as compliance evidence.

```bash
safestream redact sample.txt -o out.txt --stats --report report.json
# -- 11 detection(s): aws_key=1, credit_card=1, email=1, github_token=1, ipv4=1, …
```
```json
{ "tool": "safestream-redactor", "version": "0.3.0", "files": 1,
  "total_detections": 11, "detections_by_type": { "aws_key": 1, "email": 1, … },
  "chars_in": 657, "chars_out": 430, "decode_replacements": 0 }
```

### CI / pre-commit secret gate

```bash
safestream detect build.log --fail-on-detect   # exits 1 if anything is detected
```

### Offline network guard

During CLI redaction, any outbound **non-loopback** connection is blocked by
default (belt-and-suspenders against exfiltration). Disable with `--allow-network`.

### Supported entity types

`email, phone, credit_card, ssn, ipv4, ipv6` · credentials/secrets:
`aws_key, aws_secret, github_token, api_key, jwt, private_key, slack_token,
slack_webhook, stripe_key, google_api_key, sendgrid_key, twilio_key, npm_token,
openai_key, anthropic_key, url_credentials`, generic high-entropy `secret` · NER
(needs `[ner]`): `person, org, loc` · and user-defined `custom`. Detection runs as
a multi-tier cascade: deterministic regex+validators → custom → optional NER →
entropy → contextual scoring.

---

## Datasets

Nothing is checked in (`benchmarks/data*` is gitignored, and real corpora carry
their own licences). You either **generate** synthetic data or point the harness
at an **existing public** corpus.

### Generate synthetic corpora

Two seeded generators, each writing a matched pair — `dataset.txt` (corpus) and
`dataset.json` (gold spans, a list of `{"start","end","type","text"}`):

```bash
# clean, canonical PII (email, phone, credit_card, ssn, ipv4)
python benchmarks/generate_dataset.py --size-mb 10 --out benchmarks/data --seed 42

# adversarial: real PII embedded in noisy log/JSON/CSV/SQL records dense with
# HARD NEGATIVES (Luhn-failing order numbers, 5-octet IPs, invalid-area SSNs,
# UUIDs, git hashes) so the score measures precision, not just recall
python benchmarks/generate_hard_dataset.py --size-mb 5 --out benchmarks/data_hard --seed 7
```

**Files:** [`benchmarks/generate_dataset.py`](../benchmarks/generate_dataset.py),
[`benchmarks/generate_hard_dataset.py`](../benchmarks/generate_hard_dataset.py).
Both are seeded (`--seed`) so runs are reproducible and CI can gate on them.

### Use existing public benchmark corpora

For a **defensible** accuracy number, evaluate against an independent labeled
corpus you did *not* generate. `benchmarks/evaluate.py` ships loaders for the
standard ones:

| Corpus | What it measures | `evaluate.py` loader |
|---|---|---|
| [Presidio research dataset](https://github.com/microsoft/presidio-research) | Realistic generated PII, standard labels | `--presidio-json file` |
| CoNLL-2003 / WikiNER | PERSON/ORG/LOC recall (needs `--ner`) | `--conll file` |
| n2c2 / i2b2 de-identification | Clinical PHI — the hardest target (data-use agreement required) | `--jsonl` after conversion |

Map the corpus labels onto SafeStream types with `--label-map` and run
(see the next section).

---

## Benchmarks

The [`benchmarks/`](../benchmarks) directory has two very different tools — do not
conflate them (the [`benchmarks/README.md`](../benchmarks/README.md) explains why).

### Regression fixture — `run_benchmark.py`

Scores the detector against a **self-generated** corpus. A near-perfect score means
"still handles standard formats and resists distractors," **not** real-world
accuracy. Use it to catch regressions and compare false-positive resistance
against Presidio.

```bash
python benchmarks/generate_dataset.py --size-mb 10          # -> benchmarks/data/
python benchmarks/run_benchmark.py                          # scores benchmarks/data/
python benchmarks/run_benchmark.py --data benchmarks/data_hard   # adversarial corpus
```
```text
corpus: 1.0 MB, 6031 gold entities
safestream-redactor    P=1.000  R=1.000  F1=1.000      5.03 MB/s  (tp=6031 fp=0 fn=0)
presidio              (not installed — pip install 'safestream-redactor[bench]')
```

Include Presidio in the comparison (its compared types are pattern-based and run
offline — no ~600 MB spaCy model needed), and gate CI on quality:

```bash
pip install 'safestream-redactor[bench]'
python benchmarks/run_benchmark.py --assert-precision 0.99 --assert-recall 0.99
```

### Real accuracy — `evaluate.py`

Point it at an **independent** labeled corpus; the precision/recall it reports are
defensible. This is the number to quote when someone asks "how accurate is it?"

```bash
# any {text, spans} JSONL, mapping the corpus's labels onto SafeStream types
python benchmarks/evaluate.py --jsonl corpus.jsonl \
    --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn,CREDIT_CARD=credit_card --ner

# apples-to-apples vs another system, with CIs, significance, and error examples
python benchmarks/evaluate.py --jsonl secrets.jsonl --system safestream \
    --compare gitleaks --bootstrap 2000 --errors 10
```

Baselines available through one adapter: `--system {safestream,regex,presidio,scrubadub,gitleaks}`.
Standard-corpus loaders: `--conll`, `--presidio-json`, `--jsonl`, `--text/--gold`.

### Scaling proofs

```bash
# constant-memory: a flat peak-memory line against a growing input (Theorem 3)
python benchmarks/scale_memory.py --sizes 64 256 1024 4096

# parallel speedup + a byte-identity assertion at every worker count (Theorem 2)
python benchmarks/parallel_speedup.py --size 512 --workers 1 2 4 8
```

### Calibration

```bash
python benchmarks/calibrate.py --jsonl labeled.jsonl \
    --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn --out calibrator.json
```

### Measured headline results

From [`research/reports/benchmark-report.md`](../research/reports/benchmark-report.md)
and [`research/results/`](../research/results):

- **Clean corpus** (10.5 MB, 60,253 gold) → P/R/F1 = **1.000** @ 3.50 MB/s.
- **Adversarial corpus** (5.2 MB, 70,169 gold) → **P = 0.999** (45 FP), R = 1.000.
- **Constant memory** → **~2.75 MB** peak at both 8 MB and 32 MB inputs (flat).

Free-form names/addresses need the `[ner]` tier; without it they are not detected.
SafeStream is tuned to favour **precision** on structured PII and credentials —
treat it as high-recall for credentials/structured PII and best-effort for free
prose. See the accuracy note in the main [README](../README.md#detection-accuracy--limitations).

---

## Read more

- [`README.md`](../README.md) — full feature list and architecture diagrams
- [`docs/rest-api.md`](rest-api.md) — REST API reference
- [`benchmarks/README.md`](../benchmarks/README.md) — the definitive benchmark guide
- [`research/README.md`](../research/README.md) — measured results + competitor comparison
- [`SYSTEM_DESIGN.md`](../SYSTEM_DESIGN.md) — deep design rationale
