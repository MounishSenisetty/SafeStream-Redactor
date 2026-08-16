# SafeStream-Redactor — Complete Project Overview

This document explains **what the project is, how it is put together, and what
every file does and why it exists**. It is the single place to build a mental
model of the whole system before reading code. It is written to match the
implementation on the current branch — where a claim could drift from the code,
the responsible module is named so the two can be checked against each other.

---

## 1. What the project is

SafeStream-Redactor is a **local-first, constant-memory streaming redaction
library** (plus CLI, optional REST API, and Docker image) that detects and
removes **PII, credentials, and high-entropy secrets** from text of any size.

The defining property: it processes input in fixed-size chunks with an
overlapping context window, so **memory use does not grow with input size** — a
1 GB log redacts under the same allocation cap as a 1 KB one — while still
catching entities that straddle chunk boundaries.

Three things distinguish it from general PII engines:

1. **Credentials & secrets, not just PII.** Named credential patterns (AWS,
   GitHub, Slack, Stripe, Google, SendGrid, Twilio, npm, OpenAI, Anthropic,
   JWT, private keys) *plus* a statistical tier that flags undocumented
   high-entropy secrets by Shannon entropy.
2. **Bounded-memory streaming with correctness guarantees.** The streaming and
   parallel engines are backed by a formal model (`docs/FORMAL_MODEL.md`) with
   three theorems: streaming equivalence, parallel byte-identity, and constant
   memory.
3. **Local-first by construction.** No server, no database, no telemetry; an
   opt-out egress guard blocks non-loopback network connections during a run.

**Non-goals:** it is not a cloud DLP platform, not an anonymiser (pseudonymize
mode is reversible with the key), and the regex core does not detect free-form
names/addresses without the optional NER tier.

---

## 2. The layered architecture (how the pieces fit)

```
Users / CI / Applications
        │
   CLI  │  Python API  │  REST API        ← interfaces (cli.py, redactor.py, api.py)
        ▼
   Redactor (facade / coordination)       ← redactor.py
        ▼
   Streaming engine (rolling buffer)       ← engine.py
        ▼
   Detection pipeline (multi-tier)         ← detectors/*
        ▼
   Contextual adjust + calibration         ← detectors/contextual.py, calibration.py
        ▼
   Confidence filter + overlap resolution  ← entities.py:resolve_overlaps
        ▼
   Redaction policy (replace/mask/pseudo)  ← policy.py
        ▼
   Atomic output + content-free stats      ← redactor.py, report.py
```

Cross-cutting facilities: **configuration** (`config.py`), **egress guard**
(`netguard.py`), **across-file scheduling** (`scheduler.py`), **within-file
parallelism** (`parallel.py`), **plugin discovery** (`detectors/registry.py`).

The editable diagram sources for all of this live in
[`docs/architecture/`](architecture/) (Mermaid + PlantUML), each validated
against the module it depicts.

---

## 3. Every file, what it does, and why it is needed

### 3.1 Package core — `src/safestream_redactor/`

| File | What it does | Why it's needed |
|---|---|---|
| `__init__.py` | Declares `__version__`, re-exports the public API (`Redactor`, `Detection`, `EntityType`, `RedactionMode`, `RedactionPolicy`, `RedactionStats`, `Calibrator`), installs a `NullHandler`. | Defines the stable public surface and the single source of truth for the version (read by hatchling at build time). The `NullHandler` follows library convention — the package emits no logs unless the host app configures logging, and **detection content is never logged**. |
| `entities.py` | `EntityType` enum (all detectable kinds), the `Detection` dataclass (`start`, `end`, `text`, `entity_type`, `confidence`, `source`, `meta`), and `resolve_overlaps()`. | The vocabulary shared by every tier. `resolve_overlaps` is the arbitration step: on overlap, higher confidence wins, ties break to the longer span (a credit card beats the phone number inside it). Uses a `bisect` sweep so it stays near-linear. |
| `engine.py` | The streaming engine: `read_chunks`, `stream_windows`, `stream_transform`, and the `DEFAULT_CHUNK_SIZE`/`DEFAULT_OVERLAP` constants. | The heart of the constant-memory property. Keeps a rolling buffer of `chunk_size + overlap`; emits only text ≥ `overlap` from the buffer end; retreats the emit boundary rather than split a detection; carries the tail forward as read-only left context. Guarantees any entity ≤ `overlap` chars is seen whole even across a boundary. |
| `redactor.py` | The `Redactor` facade: builds the tier list, runs `detect()` (pool → contextual adjust → optional calibration → confidence filter → overlap resolution), and offers `redact`, `redact_stream`, `detect_stream`, and `redact_file`. | The one object users touch. `redact_file` writes to a temp file and `os.replace`s it into place (atomic — a crash never leaves a half-redacted file that looks complete), refuses in-place redaction, and dispatches to the parallel engine when `workers>1`. `detector_names` exposes the active tiers (used by the REST API). |
| `policy.py` | `RedactionMode` (REPLACE/MASK/PSEUDONYMIZE) and `RedactionPolicy` (`render`, `apply`). | Decides the replacement text for each detection: fixed string, per-type override, masking with trailing-char reveal, or deterministic HMAC pseudonyms. Fails closed: pseudonymize without an `hmac_key` raises. Carries the security caveat that pseudonyms are reversible with the key. |
| `report.py` | `RedactionStats` (per-type counts, chars in/out, decode replacements) and `build_report`/`write_report`. | **Content-free auditing.** The stats carry only type names, counts, and sizes — never matched text — so a compliance report can be filed and shipped without weakening the privacy guarantee. `decode_replacements` surfaces undecodable input that was never scanned (a coverage risk). |
| `config.py` | Strict TOML policy loading: `validate_config`, `load_config`, `policy_from_config`, `redactor_from_config`. | A DLP tool must **fail closed** on misconfiguration — a typo'd key silently defaulting means unredacted output ships. The schema is a strict allowlist; unknown sections/keys are hard errors with a `difflib` "did you mean?" hint. |
| `netguard.py` | Monkeypatches `socket.connect`/`connect_ex` to raise `NetworkAccessError` on non-loopback targets; `install`/`uninstall`/`enforced()`. | Best-effort, defense-in-depth egress guard so an accidental phone-home (by a dependency or plugin) is blocked before a byte leaves. Explicitly **not** a security boundary (a subprocess or native code can bypass it) — for a hard guarantee use `--network none`. |
| `scheduler.py` | RAM/CPU-aware `redact_tree`: a process pool over many files, worker count clamped by cores and `/proc/meminfo`. | Redaction of one file is already streaming; the scheduler parallelises *across* files so a directory tree uses every core without aggregate memory blowing up. |
| `parallel.py` | Within-file parallelism: splits one large file into character-aligned byte ranges, redacts them concurrently, and stitches seams. | Speeds up a single huge file. The **seam valve** verifies both neighbours agree on any detection crossing a seam; output is byte-identical to the sequential pass, or it falls back to sequential. Only self-synchronising encodings (UTF-8, single-byte) are split. See `docs/adr/0001-intra-file-parallelism.md`. |
| `calibration.py` | `Calibrator`: a dependency-free logistic regression over **detection-local** features → calibrated P(true positive). | Turns hand-set confidences into comparable probabilities so `min_confidence` is a principled threshold across tiers. Every feature is a function of the detection alone, so calibration **preserves** the streaming/parallel equivalence guarantees. |
| `cli.py` | The `safestream` command: `redact`, `detect`, `init-config`, `serve`; builds a `Redactor` from flags/config, streams stdin↔stdout with atomic writes, installs the egress guard by default. | The primary interface for humans and CI. `detect --fail-on-detect` is a pre-commit/CI secret gate. |
| `api.py` | Optional stdlib REST API: `dispatch` (pure router), `make_handler`, `serve`. Routes `/health`, `/version`, `/detectors`, `/redact`, `/scan`. | A thin transport adapter around the **same** `Redactor` — no duplicated engine, no new runtime dependency. Loopback by default, never logs bodies, rejects oversized bodies (413), keeps `/scan` content-free. |
| `__main__.py` | `python -m safestream_redactor` shim → `cli.main()`. | Lets the package run as a module; the console-script entry point is the normal path. |
| `py.typed` | PEP 561 marker. | Ships the inline type hints so downstream users get type checking. |

### 3.2 Detection tiers — `src/safestream_redactor/detectors/`

| File | Tier | Role |
|---|---|---|
| `base.py` | — | The `Detector` protocol: anything with a `name` and `detect(text) -> list[Detection]`. The single contract every tier and plugin implements. |
| `deterministic.py` | Tier 1 | Regex patterns **paired with validators** — Luhn for cards, area/group/serial rules for SSNs, `ipaddress` parsing for IPv6, etc. Each pattern declares literal anchors (`AKIA`, `eyJ`, `@`) so a cheap prefilter skips regexes that cannot match (secret-sparse text runs much faster with provably identical output). Covers PII **and** named credentials. |
| `entropy.py` | Tier 2 | Shannon-entropy scoring for **undocumented** high-entropy secrets with no published format. Precision kept up by min-length, mixed charset, and per-alphabet entropy floors (hex floored lower than base64). Span capped to `MAX_SPAN` so the formal model's bounded-span assumption holds. |
| `ner.py` | Tier 3 (optional) | spaCy NER for PERSON/ORG/LOC. Imported lazily (the `[ner]` extra) so the core stays dependency-free. Pickles only its config so multiprocessing workers reload the model locally. |
| `contextual.py` | Tier 4 | `ContextualScorer`: nudges confidence up (trigger words like `ssn:`, `card`) or down (placeholders like `example`, `test`), and *promotes* otherwise-ambiguous spans (a bare 9-digit number next to "ssn:") into detections. |
| `custom.py` | User | `CustomDetector`: literal words/phrases and user regexes from the CLI/API/config, always redacted at confidence 1.0. |
| `registry.py` | Plugins | Discovers third-party tiers via the `safestream_redactor.detectors` entry-point group. A failed/invalid plugin is skipped **with a warning** (never silently — a missing tier means reduced coverage). |

### 3.3 Tests — `tests/` (188+ tests)

Each `test_*.py` targets one concern: `test_detectors`/`test_ner` (tiers),
`test_redaction`/`test_report` (redaction + stats), `test_streaming`/
`test_memory` (engine + the constant-memory proof, marked `memory`),
`test_atomic_writes` (durability), `test_parallel`/`test_scheduler`
(parallelism + byte-identity), `test_config` (fail-closed validation),
`test_calibration`, `test_netguard`, `test_encoding`, `test_prefilter`
(prefilter ≡ unfiltered differential), `test_properties` (Hypothesis property
tests), `test_cli`, `test_evaluate`, and `test_api` (the REST layer). Coverage
is gated at 95%.

### 3.4 Benchmarks — `benchmarks/`

| File | Purpose |
|---|---|
| `generate_dataset.py` | Seeded **clean** labeled corpus (canonical entity formats + distractors). A regression fixture, not a real-world accuracy measure. |
| `generate_hard_dataset.py` | Seeded **adversarial** corpus: real PII embedded in noisy log/JSON/CSV/SQL dense with hard negatives (Luhn-failing 16-digit numbers, 5-octet IPs, invalid SSNs, UUIDs). Measures **precision under distractors**. |
| `run_benchmark.py` | Scores SafeStream (and Presidio if installed) on a corpus: P/R/F1 (type-aware, ≥50% span overlap) + throughput. Has CI assert gates. |
| `evaluate.py` | The **real** accuracy harness for independent labeled corpora: bootstrap CIs, paired-bootstrap significance, baseline adapters (regex/presidio/scrubadub/gitleaks), CoNLL/Presidio loaders, per-type error analysis. |
| `calibrate.py` | Trains the logistic calibrator; reports Brier/ECE before-vs-after and a per-tier ablation. |
| `scale_memory.py` | Peak memory vs file size (empirical Theorem 3 — a flat line proves constant memory). |
| `parallel_speedup.py` | Speedup vs worker count with a byte-identity assertion at every count (empirical Theorem 2). |

Measured outputs from these scripts are recorded under
[`research/`](../research/) with full environment metadata; see
[`research/README.md`](../research/README.md) and
[`research/reports/benchmark-report.md`](../research/reports/benchmark-report.md).

### 3.5 Documentation — `docs/`

`architecture/` (Mermaid + PlantUML diagram sources), `rest-api.md`,
`PROJECT_OVERVIEW.md` (this file), `FORMAL_MODEL.md` (definitions + 3 theorems +
proofs mapped to code), `RESEARCH_PLAN.md`, `ROADMAP.md`, `AUDIT.md`,
`good_first_issues.md`, and `adr/0001-intra-file-parallelism.md` (the design
record for the seam protocol). Root docs: `README.md`, `SYSTEM_DESIGN.md`
(the long-form design), `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md`.

### 3.6 Packaging, deployment, CI

| File | Role |
|---|---|
| `pyproject.toml` | Hatchling build; dynamic version; core has **zero third-party runtime deps** (`tomli` only on <3.11); extras `[ner]`, `[dev]`, `[bench]`; `safestream` console script; ruff/mypy/pytest/coverage config. |
| `Dockerfile` | Two-stage build (build wheel → slim runtime), non-root user, offline core. Entry point `safestream`, so `docker run … serve` starts the API. |
| `.dockerignore` | Keeps the build context small/reproducible. |
| `.github/workflows/` | `ci.yml` (tests/lint/type across Python versions), `docker.yml` (image build), `publish.yml` (PyPI release). `dependabot.yml` + issue templates. |
| `examples/policy.toml` | A fuller ready-to-use policy (NER + custom patterns). |
| `LICENSE` | MIT. |

---

## 4. How a redaction actually flows (end to end)

1. **Config** is read and validated (fail-closed); CLI flags overlay it.
2. A **`Redactor`** is built: tier list assembled, egress guard installed.
3. **`read_chunks`** streams the input; **`stream_windows`** maintains the
   rolling buffer + overlap and yields `(segment, detections)`.
4. For each window, **`Redactor.detect`** runs every tier, then contextual
   adjustment, optional calibration, the `min_confidence` filter, and
   `resolve_overlaps`.
5. The boundary **retreats** if it would split a detection; the tail is retained
   as left context.
6. **`RedactionPolicy.apply`** rewrites each detection; the redacted segment is
   written to a **temp file**.
7. On completion the temp file is **atomically replaced** into the output path;
   **`RedactionStats`** (content-free) is returned/reported.

`workers>1` runs step 3–6 across character-aligned ranges (`parallel.py`) or
across files (`scheduler.py`), with byte-identity to the sequential pass.

---

## 5. Deployment modes

| Mode | Entry point | Notes |
|---|---|---|
| Python library | `from safestream_redactor import Redactor` | The core API. |
| CLI | `safestream redact/detect/init-config/serve` | Streams stdin↔stdout; atomic file writes; egress guard on by default. |
| REST API | `safestream serve` / `api.serve()` | Stdlib-only, loopback default, same engine. |
| Docker | `docker run … safestream …` | Non-root, offline core; can run one-shot redaction or the API. |
| PyPI | `pip install safestream-redactor` | Core is dependency-free; extras opt-in. |

---

## 6. Where to look next

- **Correctness & memory guarantees:** `docs/FORMAL_MODEL.md` + `engine.py` /
  `parallel.py`.
- **Security posture:** `SECURITY.md` + `netguard.py` + `policy.py` (pseudonym
  caveat).
- **Accuracy & benchmarks:** `benchmarks/README.md` + `research/`.
- **Diagrams:** `docs/architecture/`.
