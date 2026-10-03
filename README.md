# SafeStream-Redactor

[![CI](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/MounishSenisetty/SafeStream-Redactor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![License](https://img.shields.io/pypi/l/safestream-redactor.svg)](https://pypi.org/project/safestream-redactor/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Streaming PII & credential redaction for massive text files — constant **O(1) memory**,
multi-tier detection (regex + validators + entropy + optional NER + contextual heuristics),
fully customizable redaction.

Redact a 100 GB log file with the same memory footprint as a 1 KB one.

```console
$ pip install safestream-redactor
$ printf 'user=bob@corp.example ssn: 123-45-6789 key=AKIAIOSFODNN7EXAMPLE\n' | safestream redact - -o -
user=[REDACTED] ssn: [REDACTED] key=[REDACTED]
$ safestream detect . --fail-on-detect      # CI gate: file:line:col, never the secret itself
```

Unlike general PII engines (Presidio, scrubadub) it also detects **credentials and
secrets** — AWS keys, GitHub/Slack/Stripe/Google/SendGrid/Twilio/npm tokens, JWTs,
private-key blocks, and *undocumented* high-entropy secrets — in the same streaming pass.

## Why?

Most PII tools load the whole document into memory. SafeStream-Redactor processes text in
fixed-size chunks with an overlapping context window, so entities that straddle chunk
boundaries are still caught — and memory use never grows with file size (proven by a test
that redacts a generated 1 GB file under a 16 MB allocation cap).

## Features

- **Constant-memory streaming** — process very large files without loading the entire file into memory.
- **Multi-tier detection** — deterministic patterns, entropy analysis, optional NER, and contextual scoring.
- **PII detection** — emails, phone numbers, credit cards, SSNs, IPv4/IPv6, and optional names/organizations/locations.
- **Credential detection** — API keys, cloud credentials, tokens, JWTs, private keys, high-entropy secrets, and symbol-containing (compound) passwords/blobs.
- **Multiple redaction modes** — replace, mask, pseudonymize, and per-type replacements.
- **Parallel processing** — process directory trees or split large files across workers.
- **Offline network guard** — prevents non-loopback network access by default during CLI redaction.
- **Explicit memory budget** — `--memory-limit 32MB` admits the run under a stated budget (sizes workers, refuses configs that can't fit) *and*, on Linux/POSIX, backs it with a hard kernel `RLIMIT_AS` cap so an over-allocating run **fails closed** (exit 3) at the kernel instead of swelling past the limit; on platforms without `RLIMIT_AS` it falls back to admission control only ([docs/MEMORY_ARCHITECTURE.md](docs/MEMORY_ARCHITECTURE.md)).
- **Web playground** — `safestream ui` opens a local Streamlit page to try detection and redaction interactively: highlighted findings, side-by-side redaction, file upload; loopback-only with telemetry off ([Web Interface](#web-interface)).
- **MCP server** — `safestream mcp-serve` exposes offline `scan`/`redact` tools to AI agents; metadata only, never the secret ([docs/MCP.md](docs/MCP.md)).
- **CI/CD secret gate** — `detect --fail-on-detect`, SARIF output, a pre-commit hook, and a GitHub Action ([docs/CI_CD.md](docs/CI_CD.md)).
- **Native core** — `--backend native` runs every default tier on a compiled Rust core with output byte-identical to the Python tier: 3–17 MB/s per core on the evaluation corpora, 3–12× pure Python ([Evaluation](#evaluation)). Unicode `` stays on the fast DFA path even on non-ASCII text ([docs/NATIVE_CORE.md](docs/NATIVE_CORE.md)).
- **File-system DLP (Linux)** — `safestream fanotify --watch DIR --mode audit|redact|block` logs, redacts in place, or denies reads of files that contain secrets; falls back to inotify without `CAP_SYS_ADMIN` ([docs/FANOTIFY.md](docs/FANOTIFY.md)).
- **More operators** — beyond replace/mask/pseudonymize: salted `hash`, reversible `encrypt` (AES-256-GCM, restored with `safestream deanonymize`) and `fictionalize` (synthetic values from reserved ranges). All are pure functions of the span, so streaming and parallel output stay byte-identical ([docs/PRESIDIO_PARITY.md](docs/PRESIDIO_PARITY.md)).
- **Regional recognizers (opt-in)** — `--regional` adds checksum-validated IBAN, Bitcoin addresses, UK NHS numbers and India Aadhaar, plus UK NINO, India PAN and Ethereum addresses by shape.
- **Extensible plugin system** — add custom detection tiers through Python entry points, loaded only when you opt in (`--enable-plugins`); each declares its streaming boundary requirements ([docs/DETECTORS.md](docs/DETECTORS.md)).
- **Configurable policies** — define detection and redaction behavior using TOML.

## Install

Three ways — pip, from source, or Docker:

```bash
# 1. pip (constant-memory core, zero third-party runtime deps)
pip install safestream-redactor

# optional local web playground (Streamlit) — `safestream ui`:
pip install 'safestream-redactor[ui]'

# optional spaCy-based PERSON/ORG/LOC detection:
pip install 'safestream-redactor[ner]'
python -m spacy download en_core_web_sm

# optional native (Rust) detection core — a byte-identical accelerator for the
# deterministic tier, selected with Redactor(backend="native"); the base install
# stays pure-Python, and backend="native" falls back to Python when it is absent:
pip install 'safestream-redactor[native]'

# optional local ONNX NER tier — on-device PERSON/ORG/LOC detection via a
# bring-your-own ONNX model, no data egress (Redactor(use_onnx=True, ...)):
pip install 'safestream-redactor[onnx]'
# ...and export a model once (needs torch + transformers, writes models/ner/):
python scripts/export_onnx.py --out models/ner
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
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/data safestream-redactor \
    redact /data/input.txt -o /data/output.txt

# released multi-arch images (amd64/arm64, with SBOM + provenance) are on GHCR:
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/data ghcr.io/mounishsenisetty/safestream-redactor \
    redact /data/input.txt -o /data/output.txt
```

## Quickstart

> **New here?** Follow the guided demo in **[docs/DEMO.md](docs/DEMO.md)** — all four
> install methods (PyPI / clone / Docker / REST API), every feature, dataset
> generation, and benchmarks in one place. Or run it in one command:
> `examples/run_demo.sh`.

### CLI

```bash
# redact everything detectable, write to out.txt
safestream redact input.txt -o out.txt

# only emails + SSNs, custom replacement, plus a custom codename
safestream redact input.txt -o out.txt --types email,ssn --replace "***" --custom-word "ProjectX"

# mask all but the last 4 characters
safestream redact cards.csv -o masked.csv --mode mask --keep-last 4

# reversible encryption, then restore it (the key stays out of the process list)
export SAFESTREAM_ENCRYPT_KEY="$(head -c 32 /dev/urandom | base64)"
safestream redact input.txt -o enc.txt --mode encrypt
safestream deanonymize enc.txt -o restored.txt

# synthetic stand-ins (example.com, TEST-NET IPs, 555-01xx phones) and regional IDs
safestream redact input.txt -o demo.txt --mode fictionalize --hmac-key "$SECRET" --regional

# deterministic pseudonyms (same input -> same token), streaming from stdin
tail -f app.log | safestream redact - -o - --mode pseudonymize --hmac-key "$SECRET"

# redact a whole directory tree in parallel (RAM/CPU-aware worker count)
safestream redact ./logs -o ./logs_redacted --workers 8

# ...or split ONE big file across cores — output is byte-identical to the
# single-core pass (a seam cross-check guarantees no lost/duplicated text)
safestream redact huge.log -o huge_redacted.log --workers 8

# list what would be redacted: type, file:line:col, confidence. The matched text
# is hidden by default so detect output is safe to log; reveal it for local triage
safestream detect input.txt
safestream detect input.txt --json --show-text

# CI / pre-commit secret gate: non-zero exit if anything is found. Directories are
# walked (skipping symlinks, .git/, binaries)
safestream detect build.log --fail-on-detect
safestream detect src/ tests/ --fail-on-detect

# SARIF report for GitHub code scanning (content-free: no secret text)
safestream detect . --sarif > results.sarif

# run within an explicit memory budget; fails closed (exit 3) if it can't fit
safestream redact big.log -o clean.log --memory-limit 64MB --workers 8

# expose scan/redact as offline MCP tools for an AI agent (stdio JSON-RPC)
safestream mcp-serve

# the compiled Rust core (pip install 'safestream-redactor[native]'); same output
safestream redact huge.log -o clean.log --backend native --workers 4

# add the gated on-device ONNX name tier (PERSON/ORG/LOC) on top of the native core
safestream redact notes.txt -o notes_clean.txt --backend native --workers 8     --onnx models/ner/model.int8.onnx --onnx-vocab models/ner/tokenizer.json     --onnx-labels models/ner/labels.json

# Linux DLP daemon: deny reads of any file under /srv/exports that holds a secret
sudo safestream fanotify --watch /srv/exports --mode block

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
spawned subprocess, or another process on the machine are outside its reach. Pass
`--allow-network` to disable it.

For a **kernel-enforced** boundary that also contains native code and raw syscalls, add
`--offline-hard MODE` (Linux; opt-in, applied before workers fork):

```bash
# block AF_INET/AF_INET6 socket creation process-wide via a seccomp-bpf filter
safestream redact input.txt -o out.txt --offline-hard seccomp

# or enter an empty network namespace (no network at all, loopback included)
safestream redact input.txt -o out.txt --offline-hard netns   # or: auto
```

- **`seccomp`** — installs a seccomp filter that makes IPv4/IPv6 socket *creation*
  fail (`EACCES`) for this process and every child, native code included. `AF_UNIX`
  and already-open sockets are untouched. (Classic seccomp-bpf can't inspect the
  `sockaddr` pointer, so it blocks IP-socket creation outright rather than filtering
  `connect()` by address — the stronger choice for offline use.)
- **`netns`** — `unshare(CLONE_NEWNET)` into a fresh namespace whose only interface is a
  down loopback: no network of any kind. Needs `CAP_SYS_ADMIN` (root) or unprivileged
  user-namespace support (tried as a fallback).
- Both **fall back with a warning** where unsupported, leaving the in-process guard
  active; neither is for `serve`/`mcp-serve` (they need loopback).

For whole-container isolation you control, `docker run --network none ...` remains the
strongest option. See
[SECURITY.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/SECURITY.md) for the full threat model.

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

# split a single large file across cores; byte-identical to the sequential pass
Redactor().redact_file("huge.log", "huge_redacted.log", workers=8)

# native core + gated ONNX name tier (paths from scripts/export_onnx.py)
r = Redactor(
    backend="native",
    use_onnx=True,
    onnx_model="models/ner/model.int8.onnx",
    onnx_vocab="models/ner/tokenizer.json",
    onnx_labels="models/ner/labels.json",
)
r.redact("signed by john smith, key AKIAIOSFODNN7EXAMPLE")

# enforce the offline guarantee around any block of code
from safestream_redactor import netguard
with netguard.enforced():
    Redactor().redact_file("huge.log", "huge_redacted.log")   # network calls now raise
```

### REST API

An optional, standard-library-only REST server wraps the same `Redactor` (no
extra dependency, loopback-only by default, request bodies never logged):

```bash
safestream serve                       # http://127.0.0.1:8000
curl -s -X POST http://127.0.0.1:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "email bob@corp.io key AKIAIOSFODNN7EXAMPLE"}'
# {"redacted": "email [REDACTED] key [REDACTED]", "total_detections": 2, ...}
```

Endpoints: `GET /health`, `GET /version`, `GET /detectors`, `POST /redact`,
`POST /scan` (offsets + types only, never the matched text). Full reference:
[docs/rest-api.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/rest-api.md).

### Extending with plugins

Any installed package can add a detection tier by advertising an entry point — no fork
required. Loading is **opt-in**: plugin code runs with full privileges inside a tool that
handles your secrets, so installing a package (perhaps as a transitive dependency) must
not be enough to run it. Enable plugins with `Redactor(load_plugins=True)`,
`safestream ... --enable-plugins`, or `[plugins] enabled = true` in a policy file. If
plugins are installed but not enabled, a one-time warning names them.

```toml
# in your plugin package's pyproject.toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_pkg.detectors:MyDetector"   # a Detector instance or zero-arg factory
```

A detector is anything with a `name` and `detect(text) -> list[Detection]` (the
`Detector` protocol).

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

A fuller, ready-to-use policy — NER enabled, plus custom patterns for passport /
driver-licence / bank-account / routing / employee-ID / Slack-ID / DOB values — ships in
[`examples/policy.toml`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/examples/policy.toml). Generate a minimal starter with
`safestream init-config -o policy.toml`.

Policy files fail closed: an unknown section or key (`replacment`), or a value of the
wrong type (`use_entropy = "no"`, `min_confidence = "0.5"`), is an error before any
input is read, never a silent fallback to defaults. CLI flags layer on top of the file:
scalar flags override it, `--custom-word`/`--custom-regex` add to it, and `--types`
scopes every tier exactly as it does without `--config`.

## Web Interface

A local playground for trying the engine without writing code: paste text or upload a
file, then tune detection in the sidebar and watch the results update.

```bash
pip install 'safestream-redactor[ui]'      # or, from a clone: pip install -e '.[ui]'
safestream ui                               # opens http://127.0.0.1:8501
safestream ui --port 9000 --headless        # another port, no browser tab
safestream ui --max-upload-mb 4096          # accept uploads up to 4 GB (default 2 GB)
python -m safestream_redactor.ui            # same as `safestream ui`
```

![Detect mode: findings highlighted by severity, with counts and line:column locations](docs/images/web-ui-detect.png)

- **Detect mode** highlights each finding, coloured by severity (hover for type,
  confidence, and `line:col`). A findings table lists type, severity, confidence,
  `line:col`, character span, and detector. Matched values stay hidden unless you
  toggle *Reveal matched values*, the same default as `safestream detect`.
- **Redact mode** shows the original and the sanitized text side by side. It supports
  **Replace** (`[REDACTED]` or your own token), **Mask** (never more than half a value
  visible), and **Hash** (keyed HMAC pseudonyms, stable for equal values). You can copy
  the output from its code block or download it as `<name>.redacted.<ext>`.
- **Inspect mode** replays the streaming engine one detection pass at a time, so you
  can watch how a file is processed in constant memory:
  - **Left pane:** the window the pass scanned, in three bands: dim read-only context
    (8,192 chars), the emitted segment, and the dotted tail carried to the next pass.
  - **Right pane:** what that pass writes to the output.
  - **Boundaries:** when an entity would be cut by a boundary, a red dashed line marks
    the planned cut and a green line the actual one, and the next pass reports the
    entity it emitted whole.
  - **Controls:** Play/Pause, Step, Step back, a seek bar, and a delay slider
    (50–2,000 ms, default 500).
  - **History:** the last 5 segments stay in full text, and every pass is listed in a
    table when paused.
  - **Chunk size:** 1× or 2× the overlap. The engine never emits less than the overlap
    per pass, so smaller chunks change nothing.

  For large uploads, Inspect covers the first 200,000 characters.
- **The sidebar** sets the minimum confidence, which entity types run, high-entropy
  secret detection, the dependency-free name heuristics, spaCy NER (when the `[ner]`
  extra is installed), custom words and regexes (one per line), and the streaming chunk
  size and overlap.
- **Inputs:** a paste box (with a sample log) and uploads of `.txt`, `.log`, `.json`,
  and `.csv`, up to 2 GB by default (`--max-upload-mb`). Binary files are refused, and
  bytes that are not valid UTF-8 are reported rather than silently skipped.
- **Large files:** pasted text and uploads up to 5 MiB are analysed entirely in the
  page. A bigger upload goes to a large-file path, which starts only when you click
  *Process*:
  - the file is copied to a private temporary folder and redacted by the same parallel
    streaming engine as the CLI, on every core, with output byte-identical to it;
  - the counts cover the whole file, and highlights cover its first 200,000 characters;
  - Redact mode saves the redacted file to a folder you choose (by default, where you
    ran `safestream ui`), and offers a browser download for outputs up to 200 MiB.

  Measured on a 1 GB log with 4 cores: about 4 minutes, and each redaction worker uses
  22 MiB of private memory. Streamlit itself keeps an upload in memory while it is
  selected, about twice the file size (≈2 GB of RAM for a 1 GB upload). For files near
  your free RAM, use the CLI, which never holds the file in memory:
  `safestream redact big.log -o clean.log --workers 4`.
- **Errors:** invalid settings, such as a malformed regex or an overlap below the safe
  minimum, appear as alerts that quote the engine's own validation message, never as a
  traceback.

![Redact mode: original and redacted text side by side](docs/images/web-ui-redact.png)

**Local-only by construction.** Streamlit's own defaults would listen on every network
interface, collect usage statistics from your browser, and show a button that publishes
the app to Streamlit Community Cloud. `safestream ui` turns all three off, caps uploads
at the server, and installs the offline network guard in the page's process. The page
then checks its running configuration. It shows the green *Local-only processing*
banner only if every guarantee holds, and otherwise lists what is missing (for example,
after a plain `streamlit run`). The UI adds no detection logic of its own: findings come
from the same streaming engine the CLI uses, so results match `safestream detect` and
`safestream redact`.

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
        │ Tier 3  NER (optional)    │  spaCy, or ONNX INT8 run only on
        │                           │  ~6% micro-windows around name cues
        ├───────────────────────────┤
        │ Tier 4  contextual        │  trigger words boost/suppress
        │                           │  confidence ("ssn:", "example", ...)
        └───────────────────────────┘
                     │
          confidence filter + overlap resolution
          (deterministic wins; overlapping name spans merge, never half-redact)
                     │
                     ▼
          redaction policy (replace / mask / pseudonymize / per-type)

  Scheduler: RAM/CPU-aware multiprocessing across files (safestream/scheduler.py).
  Parallel: one big file split into character-aligned ranges, output byte-identical
    to the sequential pass, seam cross-check falls back on disagreement (parallel.py).
  Offline guard: any non-loopback connection raises NetworkAccessError (netguard.py).
  Plugins: opt-in third-party tiers from the 'safestream_redactor.detectors' entry point.
```

The same system as a layered diagram (rendered on GitHub; shown as diagram source on PyPI):

```mermaid
flowchart TB
    subgraph Interface["Interface Layer"]
        CLI["CLI"]
        API["Python / REST API"]
    end
    subgraph Support["Supporting facilities"]
        Config["Configuration"]
        Sched["Parallel scheduling"]
        Egress["Egress safeguard"]
    end
    Task["Coordination (Redactor)"]
    Stream["Streaming engine<br/>rolling buffer + overlap"]
    subgraph Detection["Detection tiers"]
        Det["Deterministic + validators"]
        Ent["Entropy (secrets)"]
        NER["NER (optional)"]
        Ctx["Contextual"]
        Arb["Arbitration<br/>score • filter • resolve"]
    end
    Redact["Redaction policy<br/>replace / mask / pseudonymise"]
    Local["Local file system"]

    CLI --> Task
    API --> Task
    Config --> Task
    Sched --> Stream
    Egress -.-> Stream
    Task --> Stream
    Stream --> Det & Ent & NER & Ctx
    Det & Ent & NER & Ctx --> Arb
    Arb --> Redact --> Local
    Stream --> Local
```

Full editable **Mermaid + PlantUML** sources for the component, class, sequence,
deployment, activity, and data-flow diagrams live in
[docs/architecture/](https://github.com/MounishSenisetty/SafeStream-Redactor/tree/main/docs/architecture).

Each tier-1 pattern declares literal *anchors* every match must contain (`AKIA`, `eyJ`,
`@`, `://`, a digit, …); a cheap substring scan per window skips regexes that cannot
match, so secret-sparse text runs ~25× faster with provably identical output (a
differential test compares prefiltered and unfiltered detection).

The streaming engine keeps a rolling buffer of `chunk_size + overlap` characters. Only text
at least `overlap` characters from the buffer's end is emitted each round; the tail is carried
into the next round so any entity up to `overlap` characters long (default 8 KB) is always
seen whole at least once, even when a chunk boundary cuts straight through it. An emit
boundary that would split a detection retreats to the detection's start. Already-emitted
text is kept (up to `overlap` chars) as read-only left context so the contextual tier scores
identically to whole-text mode.

## Supported Detection Types

| Category | Detection Types |
|---|---|
| PII | Email, phone, credit card, SSN, IPv4, IPv6, MAC address, postal address (street line, US city/state/ZIP) |
| Labeled identifiers | Student/patient/account/MRN/passport numbers, case/docket/policy/claim/visa/record numbers, DOB (the value after an explicit label) |
| NER | Person, organization, location |
| Cloud credentials | AWS keys, AWS secrets, Google API keys |
| Service tokens | GitHub, Slack, Stripe, SendGrid, Twilio, npm |
| Authentication | JWT, private keys, URL credentials |
| Generic secrets | API keys, high-entropy secrets |
| Custom | User-defined words and regex patterns |

## Evaluation

> **Read this before quoting any number below.** These are **Phase 0 dev-split**
> results: tuning happens on dev, and the held-out test splits are scored once, at the
> end of the work. Every number comes from one run of `benchmarks/harness.py`
> (commit `cebe741`, 2026-10-03) on an i7-12650H under Windows 11 on AC power in the
> *Best power efficiency* power mode, with every tool in its own virtualenv and pinned
> to **one thread**. Absolute speeds are therefore throttled; ratios between tools come
> from the same run and the same conditions. Raw JSON and tables:
> [`research/results/raw/`](research/results/raw/); analysis and error examples:
> [`research/reports/gap-report.md`](research/reports/gap-report.md).

**Corpora.** The headline sets are independent of this repo: the
[presidio-research](https://github.com/data-privacy-stack/presidio-research) synthetic
dataset (750 dev documents), the English validation set of AI4Privacy
pii-masking-300k (3,973 dev documents; academic licence, acknowledgement: AI4Privacy)
and a secrets corpus of real-format credentials from
[Nosey Parker](https://github.com/praetorian-inc/noseyparker)'s rule examples plus
generated non-secrets (313 dev documents). RedactionBench is reported as **previously
exposed**: all 200 documents were used to tune rules before the split existed. CoNLL-2003
is **not independent for the ONNX tier**: its model was trained on CoNLL. 95% CIs are
document bootstrap; P / R / F1 are character-level (did the sensitive characters get
hidden?). "Full" is the share of gold entities with *every* character redacted.

**Pattern tier** (no ML on either side; SafeStream's rule tiers against Presidio's own
pattern and checksum recognizers called directly):

| Corpus | SafeStream (native) char F1 | Presidio-regex char F1 | SafeStream P / R | Presidio P / R | Speed |
| --- | --- | --- | --- | --- | --- |
| presidio-research | 0.278 [0.243, 0.314] | 0.303 [0.267, 0.338] | 0.992 / 0.162 | 0.915 / 0.181 | 27× |
| ai4privacy | 0.467 [0.453, 0.480] | **0.553** [0.542, 0.563] | 0.966 / 0.308 | 0.747 / 0.439 | 63× |
| ai4privacy, `--dates` | **0.581** [0.570, 0.592] | 0.553 [0.542, 0.563] | 0.956 / 0.418 | 0.747 / 0.439 | 24× |
| secrets | **0.637** [0.560, 0.706] | 0.215 [0.152, 0.287] | 0.524 / 0.814 | 0.292 / 0.171 | 80× |
| RedactionBench (exposed) | **0.556** [0.479, 0.622] | 0.331 [0.289, 0.372] | 0.730 / 0.449 | 0.356 / 0.310 | 169× |

SafeStream is far more precise and 24–169× faster per core, but **Presidio-regex has
the higher F1 on ai4privacy** with the default configuration (it detects dates, URLs,
IBANs and digit-run IDs that the default tier does not) and the two are level on
presidio-research.

**NER tier** (SafeStream: native rules + gated on-device ONNX `dslim/distilbert-NER`,
INT8; Presidio: its full engine on spaCy `en_core_web_sm` / `_lg` and on two
transformers models). Best Presidio per corpus shown; all configurations are in the
raw tables.

| Corpus | SafeStream + ONNX char F1 | Best Presidio char F1 | Full (SafeStream / Presidio) | Speed vs `presidio-sm` | Tool memory |
| --- | --- | --- | --- | --- | --- |
| presidio-research | **0.718** [0.693, 0.742] | 0.708 [0.686, 0.728] (trf-deid) | 0.500 / 0.545 | 1.9× | 151 / 127 MB |
| ai4privacy | 0.576 [0.566, 0.586] | **0.733** [0.726, 0.740] (trf-deid) | 0.338 / **0.607** | 0.74× | invalid† |
| secrets | 0.636 [0.560, 0.705] | 0.596 [0.526, 0.658] (trf-deid) | 0.542 / **0.735** | 4.7× | 153 / 127 MB |
| RedactionBench (exposed) | **0.611** [0.531, 0.662] | 0.460 [0.394, 0.520] (trf-deid) | 0.608 / **0.727** | 1.4× | 150 / 205 MB |
| CoNLL (not independent) | 0.796 [0.770, 0.818] | 0.652 [0.609, 0.691] (trf-bert) | 0.648 / 0.651 | 0.32× | 150 / 130 MB |

† Each tool's process also parsed the whole ai4privacy file, and that transient peak
dominates every system's RSS there.

**Where SafeStream loses today:** Presidio's transformers engine redacts more entities
*fully* on every headline corpus (it also flags every secret-free document in the
secrets set), and wins ai4privacy outright: SafeStream misses values inside structured
fields (`"LastName": "…"`, `<Phone>…</Phone>`, `Postcode: '…'`), unlabelled ID numbers,
most international phone formats and many names. Presidio's transformers engine is
also 13–86× *slower* per core than the ONNX tier on the prose corpora. Mandatory recall on RedactionBench is
0.875 [0.761, 0.936] for SafeStream + ONNX and 0.908 [0.825, 0.958] for Presidio-trf-deid.

**Secrets.** 54.2% [48.1, 60.6] of real-format secrets are fully redacted by the
pattern tier (Presidio-regex: 13.1%); 119 of 260 dev secrets leak, mostly vendor keys
without a detector, connection strings and `password = '…'` assignments, and the
entropy tier flags 81% of generated UUIDs, hashes and base64 images. Both are the first
targets of the current work.

**Throughput.** One thread, per-document streaming detection, power-saving mode:

| Corpus | Pure Python | Native core | Native + ONNX |
| --- | --: | --: | --: |
| RedactionBench (long prose) | 1.23 MB/s | 10.9 MB/s | 0.032 MB/s |
| ai4privacy (short records) | 1.39 MB/s | 9.54 MB/s | 0.020 MB/s |
| CoNLL (news) | 1.40 MB/s | 16.6 MB/s | 0.0074 MB/s |
| presidio-research (one sentence per document) | 1.10 MB/s | 3.02 MB/s | 0.013 MB/s |

The native core is 3–12× pure Python, and the ONNX tier is model-bound (it is for
prose, not bulk logs).

**Throughput, Best performance mode, 1 thread / 16 threads** (`benchmarks/throughput.py`,
a fixed ~2 MB dev sample per corpus, 120 s budget per run; raw data in
[`research/results/raw/2026-10-03_throughput.json`](research/results/raw/2026-10-03_throughput.json)):

| System | presidio-research | ai4privacy | RedactionBench | CoNLL |
| --- | --: | --: | --: | --: |
| SafeStream native | 6.61 / 6.55 MB/s | 14.0 / 13.3 | 17.2 / 18.1 | 27.2 / 27.4 |
| SafeStream + ONNX | 0.013 / 0.020 | 0.015 / 0.051 | 0.023 / 0.096 | 0.0095 / 0.037 |
| Presidio regex | 0.125 / 0.138 | 0.136 / 0.145 | 0.058 / 0.063 | 0.092 / 0.090 |
| Presidio `sm` | 0.015 / 0.013 | 0.023 / 0.023 | 0.020 / 0.020 | 0.020 / 0.021 |
| Presidio transformers (de-id model) | 0.0007 / 0.0024 | 0.0010 / 0.0047 | 0.0008 / 0.0039 | 0.0009 / 0.0032 |

Threads help only the model runtimes: Presidio's transformers engine gains 3–5×, the
ONNX tier 1.6–4×; at equal threads the ONNX tier stays 8–30× faster than it. SafeStream's
own multi-core path is processes (`--workers N`), not threads; its scaling is not yet
re-measured, and earlier single-file figures (10–35 MB/s per core, 36–121 MB/s on 4
workers, 5.9 → 59 MB/s on 1 → 8 workers) came from other machines or a battery run and
are not quoted until it is. A Vectorscan/re2
backend was prototyped and rejected
([docs/PERFORMANCE_BACKENDS.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/PERFORMANCE_BACKENDS.md)).

**ONNX inference is one window per call by default.** An INT8 model made by dynamic
quantization scores a window differently depending on the other windows in its batch,
which made output depend on chunking (and parallel differ from sequential).
`--onnx-batch-size N` restores batching as an explicit, non-deterministic opt-in; on
the dev corpora above it changed speed by −15% to +32% with no consistent direction and
accuracy by under 0.01 F1, so nothing is lost by the deterministic default.

> **Reproducible results & comparison.** Measured accuracy/throughput and a
> constant-memory scaling curve — each recorded with full environment metadata and the
> exact command to reproduce it — plus a documented capability matrix against 10 systems
> (Presidio, Philter, Piiranha, GLiNER, Grepture, Private AI, AWS Comprehend, Google DLP,
> Microsoft Purview, Tonic AI) live in [`research/`](https://github.com/MounishSenisetty/SafeStream-Redactor/tree/main/research). Only SafeStream's numbers
> are measured; competitor rows are labelled *documented*. A complete per-file walkthrough
> of the whole project is in [`docs/PROJECT_OVERVIEW.md`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/PROJECT_OVERVIEW.md).

## Detection accuracy & limitations

**100% recall and 100% precision together are not achievable for free-text PII, by
anyone.** Names, street addresses, bank account numbers, and employee IDs have no
distinctive form — a bank account number is indistinguishable from any other run of
digits, and "April" is both a name and a month. Any detector faces a precision/recall
tradeoff: catch every possible name and you also redact ordinary words; redact only
unambiguous matches and you miss the rest. SafeStream is tuned to favour precision on
structured PII and credentials, with names and format-less identifiers handled by the
opt-in levers below. Treat it as high-recall for credentials and structured PII, and
best-effort for free prose — not as a guarantee of catching everything.

**Why a file labelled "TEST" under-detects.** The contextual tier deliberately
*subtracts* confidence from any value sitting next to `test`, `sample`, `example`,
`dummy`, `fake`, `placeholder`, or `lorem` (see `detectors/contextual.py`). This keeps
documentation snippets and fixture data from being redacted. The side effect is that a
file *saturated* with those marker words — e.g. a sample log full of `TEST DATA`,
`fake`, `example`, `TestPass` — has most of its detections pushed below the default 0.5
threshold and left untouched.That is working as designed: on real data (without the
marker words) recall is substantially higher.If you *want* those suppressed values
redacted anyway, lower `min_confidence` (below).

**Three levers to raise recall**, in increasing order of effort:

1. **Lower `min_confidence`.** The default is 0.5. Setting it to `0.35`
   (`--min-confidence 0.35`, or in a policy file) recovers most values the test/sample
   suppression demotes, at some cost to precision. Do this per-run on data you know is
   noisy — not globally on trusted prose.
2. **Enable NER for names.** Person / org / location names need the optional spaCy tier:
   `pip install 'safestream-redactor[ner]'` then `python -m spacy download en_core_web_sm`,
   and run with `--ner` (or `use_ner = true` in a policy). Without it, names are not
   detected at all.
3. **Add custom patterns for format-less identifiers.** Passport numbers, driver
   licences, bank/routing/account numbers, employee IDs, Slack user IDs, and dates of
   birth have no universal signature, so they need label-anchored regexes you supply. A
   ready-to-use policy covering all of these ships in
   [`examples/policy.toml`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/examples/policy.toml):

   ```bash
   safestream detect input.txt --config examples/policy.toml
   ```

   It also enables NER and documents each lever inline. Custom patterns redact the whole
   match (including the label word) — the fail-safe outcome for DLP.

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
pip install -e '.[ui]' && pytest tests/test_ui_app.py   # web UI page tests (Streamlit)
```

See [CONTRIBUTING.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/CONTRIBUTING.md). Good first issues live in
[docs/good_first_issues.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/good_first_issues.md) and the issue tracker.
The audited state of the codebase and the phased improvement plan are in
[docs/AUDIT.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/AUDIT.md) and [docs/ROADMAP.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/ROADMAP.md); the security
policy and threat model (what the offline guard does and does not cover) are in
[SECURITY.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/SECURITY.md).

## License

[MIT](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/LICENSE)
