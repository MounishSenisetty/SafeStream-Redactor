# SafeStream-Redactor — System Design Document

**Status:** Living document · **Version:** aligns with package `0.1.0` · **Audience:** contributors, integrators, and reviewers

---

## 1. Overview

SafeStream-Redactor is a Python library and CLI that detects and redacts
**PII, credentials, and secrets** in text of *any size* using **constant (O(1))
memory**. A 100 GB log file is processed with the same memory footprint as a
1 KB one.

Two properties differentiate it from general-purpose PII engines (Presidio,
scrubadub):

1. **Constant-memory streaming.** Text is processed in fixed-size chunks with an
   overlapping context window, so entities that straddle chunk boundaries are
   still caught, and peak memory never grows with input size.
2. **Credential & secret detection.** AWS keys, GitHub/Slack/Stripe/Google/
   SendGrid/Twilio/npm tokens, JWTs, private-key blocks, and *undocumented*
   high-entropy secrets are detected in the same streaming pass — a class of
   data most PII tools ignore entirely.

A defense-in-depth **offline network guard** can provably prevent sensitive text
from leaving the machine while redaction runs.

### 1.1 Goals

- Redact arbitrarily large files/streams within a bounded, predictable memory
  budget (`chunk_size + overlap` + largest single detection).
- High precision under adversarial, false-positive-tempting input (order
  numbers, UUIDs, git hashes, ISO timestamps, invalid-area SSNs).
- Zero third-party **runtime** dependencies for the core (NER is an opt-in
  extra); works fully offline.
- Extensible detection tiers via a plugin protocol — no fork required.
- Flexible redaction: replace, mask, or deterministic pseudonymization, with
  per-type overrides.

### 1.2 Non-goals

- Not a network DLP appliance or an inline proxy — it is a file/stream processor.
- Not a structured-database scrubber — input is treated as free text.
- Not a guaranteed-complete PII detector — regex/validator/entropy tiers target
  standard formats; free-form names/locations need the optional NER tier.
- No de-tokenization / reversible encryption of redacted values (pseudonyms are
  one-way HMACs by design).

---

## 2. High-level architecture

```
 input chunks ──▶ [ rolling buffer + overlap window ] ──▶ redacted chunks
       (file / stdin / iterable)   │
                                   ▼
                    ┌───────────────────────────┐
                    │ Tier 1  Deterministic     │  regex + validators (Luhn,
                    │                           │  SSN rules, ipaddress) + creds
                    ├───────────────────────────┤
                    │ Tier 2  Statistical       │  Shannon-entropy scoring for
                    │         (Entropy)         │  undocumented high-entropy secrets
                    ├───────────────────────────┤
                    │ (opt) Custom / NER /      │  user words+regex, spaCy PERSON/
                    │        Plugins            │  ORG/LOC, third-party tiers
                    ├───────────────────────────┤
                    │ Tier 3  Contextual        │  trigger words boost/suppress
                    │                           │  confidence & promote spans
                    └───────────────────────────┘
                                   │
                    confidence filter + overlap resolution
                                   │
                                   ▼
                    Redaction policy (replace / mask / pseudonymize / per-type)

  Scheduler:     RAM/CPU-aware multiprocessing across files (scheduler.py)
  Offline guard: any non-loopback connect() raises NetworkAccessError (netguard.py)
  Plugins:       third-party tiers via the 'safestream_redactor.detectors' entry point
```

### 2.1 Module map

| Module | Responsibility |
| --- | --- |
| `redactor.py` | `Redactor` — public façade; assembles the detector pipeline, runs detect → score → filter → resolve, and drives streaming/file/tree redaction. |
| `engine.py` | Constant-memory streaming primitives: `read_chunks`, `stream_windows`, `stream_transform`. Boundary-safe rolling buffer. |
| `entities.py` | Core types: `EntityType`, `Detection`, and `resolve_overlaps`. |
| `policy.py` | `RedactionPolicy` / `RedactionMode` — how a detected span is rewritten. |
| `detectors/base.py` | `Detector` protocol (structural typing). |
| `detectors/deterministic.py` | Tier 1: regex patterns + validators + credential signatures. |
| `detectors/entropy.py` | Tier 2: Shannon-entropy secret detector. |
| `detectors/contextual.py` | Tier 3: `ContextualScorer` — confidence adjustment + trigger-gated spans. |
| `detectors/custom.py` | User-supplied literal words/phrases and regexes. |
| `detectors/ner.py` | Optional spaCy PERSON/ORG/LOC tier (lazy import). |
| `detectors/registry.py` | Plugin discovery via entry points. |
| `scheduler.py` | RAM/CPU-aware `ProcessPoolExecutor` across a directory tree. |
| `netguard.py` | Socket-layer egress guard (offline guarantee). |
| `config.py` | TOML policy-file loading. |
| `cli.py` / `__main__.py` | Argument parsing and command dispatch (`redact`, `detect`). |

---

## 3. The streaming engine (constant memory)

The heart of the system lives in `engine.py`. It converts an iterable of text
chunks into an iterable of *exactly-once* segments with detections, using memory
bounded by `chunk_size + overlap`.

### 3.1 Rolling buffer with overlap

`stream_windows(chunks, detect, overlap)` maintains:

- **`buffer`** — the current chunk plus the tail carried over from the previous
  iteration.
- **`prefix`** — up to `overlap` characters of *already-emitted* text, kept
  read-only so backward-looking detectors (notably the contextual scorer) see
  the same left context they would in whole-text mode. Its own detections are
  dropped (offsets shifted back and any negative-start detection discarded).

Each iteration:

1. Append the new chunk to `buffer`.
2. If `len(buffer) <= overlap`, keep accumulating (nothing safe to emit yet).
3. Plan to emit everything up to `emit_upto = len(buffer) - overlap`, leaving an
   `overlap`-sized tail unread.
4. Run detection on `prefix + buffer`.
5. **Boundary safety:** for any detection straddling `emit_upto`
   (`det.start < emit_upto < det.end`), retreat `emit_upto` to `det.start` so a
   match is never cut in half.
6. Emit `buffer[:emit_upto]` with the detections fully contained in it.
7. Slide: `prefix` becomes the last `overlap` chars of what was emitted; `buffer`
   becomes the unread tail.
8. After the last chunk, flush the remaining buffer.

### 3.2 The guarantee

> Any entity whose text is at most `overlap` characters long is detected even
> when it is split across chunk boundaries.

Because the unread tail is always at least `overlap` characters, any entity of
length ≤ `overlap` is, in some iteration, seen whole within a single detection
pass. The boundary-retreat rule then ensures it is never emitted split. Defaults:
`chunk_size = 64 KiB`, `overlap = 4 KiB` — so entities up to 4 KB (enough for a
PEM private-key block) are always caught intact.

### 3.3 Memory bound

Peak resident text is `chunk_size + overlap` plus the largest single detection
(which forces a longer buffer only transiently). This is validated by
`tests/test_memory.py`, which redacts a generated ~1 GB file and asserts peak
Python heap allocation stays under **16 MB** (`tracemalloc`). CI runs a 64 MB
variant on every push across Python 3.10–3.13.

### 3.4 Consequence for detectors

Detectors must be **stateless per call** and operate on the text handed to them.
They must return **non-overlapping** detections within their own output; the
pipeline (`resolve_overlaps`) reconciles across detectors. Offsets are always
relative to the text passed in; the engine translates them back to the caller's
coordinate frame as its window slides.

---

## 4. Detection pipeline

`Redactor.detect(text)` orchestrates all tiers:

```
raw = concat(detector.detect(text) for detector in self._detectors)
scorer.adjust(text, raw)                         # boost/suppress confidences in place
confident = [d for d in raw if d.confidence >= min_confidence]   # default 0.5
return resolve_overlaps(confident)               # one detection per region
```

### 4.1 Tier 1 — Deterministic (regex + validators)

`DeterministicDetector` pairs each regex `Pattern` with an optional **validator**
so a syntactic match alone is insufficient:

- **`credit_card`** — 13–19 digits with optional separators, must pass the
  **Luhn** checksum.
- **`ssn`** — `NNN-NN-NNNN`, rejected for impossible area (`000`, `666`, `9xx`),
  group (`00`), or serial (`0000`).
- **`ipv4`** — strict octet ranges via regex; negative-lookarounds avoid version
  strings and sub-fields.
- **`ipv6`** — a loose hex candidate that must parse via `ipaddress.IPv6Address`.
- **`phone`** — two patterns: a high-confidence *structured* form (leading `+CC`
  or `(area)`) at 0.6, and a low-confidence *bare* form at 0.45 that only
  survives if the contextual tier finds a nearby phone cue. Both reject ISO-date
  and SSN shapes and require 7–15 digits.
- **`email`**, **`jwt`**, **`private_key`** (PEM blocks).
- **Credentials:** `aws_key` (`AKIA…`), `github_token` (`ghp_…`, `github_pat_…`),
  `slack_token`/`slack_webhook`, `stripe_key`, `google_api_key`, `sendgrid_key`,
  `twilio_key`, `npm_token` — each a vendor-specific signature at 0.9–0.98.
- **`api_key`** — generic `key = value` / `token: "…"` assignments (0.75), using
  a capture group so only the value is redacted, not the label.

Confidences are calibrated so that specific, self-validating formats sit well
above the 0.5 threshold, while ambiguous shapes sit below it and depend on
context.

### 4.2 Tier 2 — Statistical (entropy)

`EntropyDetector` catches bespoke, undocumented secrets with no published format
(random API keys, session tokens, generated passwords) by scoring each candidate
token's **Shannon entropy** (bits/char). Precision safeguards:

- Minimum length (24 chars) and a candidate boundary of secret-looking chars.
- Reject letters-only runs (prose/identifiers).
- Alphabet-tuned entropy floors: hex strings (`≥ 32` chars, entropy `≥ 3.0`) get
  a lower floor than base64-ish tokens (entropy `≥ 4.0`), since hex is inherently
  lower-entropy.

Emitted as `EntityType.SECRET` at 0.6 with entropy recorded in `meta`. Because
named-credential patterns score higher, overlap resolution keeps the more
specific label when a token is both. On by default; disable with `--no-entropy`.

### 4.3 Optional tiers — Custom, NER, Plugins

- **`CustomDetector`** — user literal words/phrases (compiled into one alternation)
  and regexes, emitted as `EntityType.CUSTOM` at confidence 1.0.
- **`NERDetector`** — optional spaCy tier for `PERSON`/`ORG`/`LOC`
  (`GPE`/`LOC`/`FAC` → `loc`). spaCy is imported lazily; only the NER pipe is
  loaded for speed. Requires the `[ner]` extra plus a model.
- **Plugins** — any installed package advertising a
  `safestream_redactor.detectors` entry point (a `Detector` instance or zero-arg
  factory). Loaded automatically; failures are skipped rather than fatal.

### 4.4 Tier 3 — Contextual

`ContextualScorer` does two jobs:

1. **`adjust`** (post-detection) — inspects a left window (48 chars) for
   per-type **boost** triggers (`"ssn:"`, `"card"`, `"phone"`, …) adding +0.2, and
   a tight window (16 chars) plus the match text for **suppress** triggers
   (`"example"`, `"test"`, `"dummy"`, …) subtracting −0.4. The tight suppression
   window prevents a neighbouring `"example"` from poisoning an unrelated entity.
2. **`detect`** (trigger-gated) — promotes otherwise-ambiguous spans, e.g. a bare
   9-digit number next to an SSN cue becomes an `ssn` detection at 0.8.

### 4.5 Overlap resolution

`resolve_overlaps` keeps at most one detection per region: higher confidence
wins, ties break toward the **longer** span (a credit card beats the phone
number hiding inside it). Implemented with a sorted keep-list and `bisect` for
efficiency — a candidate can only collide with the interval just before its end
point.

---

## 5. Redaction policies

`RedactionPolicy.render(detection)` decides the replacement string, in priority
order:

1. **Per-type override** — `replacements[EntityType]` (e.g. `email → "<EMAIL>"`).
2. **`replace`** (default) — a fixed string, default `[REDACTED]`.
3. **`mask`** — keep the last *N* chars, star out the rest (`mask_keep_last`,
   `mask_char`) — e.g. card → `************1111`.
4. **`pseudonymize`** — deterministic, one-way `<TYPE_HMACSHA256[:10]>` token so
   the same input always maps to the same pseudonym. **Requires an `hmac_key`**;
   enforced at construction.

`apply(text, detections)` rewrites in a single left-to-right pass over the sorted,
non-overlapping detections — O(n) in text length, no regex re-scan.

---

## 6. Concurrency & scheduling

`scheduler.redact_tree` parallelises *across files* (each file is already
constant-memory) with a `ProcessPoolExecutor`:

- **Worker sizing** (`ram_aware_workers`) — an explicit `--workers` is honoured
  (floored at 1); otherwise the count is `min(cpu_count, available_ram /
  per_worker_budget)`, where `available_ram` is read from `/proc/meminfo` when
  present and `per_worker_budget ≈ 96 MB + chunk_size + overlap`. This keeps peak
  aggregate memory bounded regardless of corpus size.
- **Fast path** — a single worker (or single file) runs in-process, avoiding pool
  overhead.
- Each worker initialises its own `Redactor` and optionally installs the offline
  guard; the output tree mirrors the input tree; one `RedactResult` is returned
  per file.

---

## 7. Security & privacy design

### 7.1 Offline network guard (`netguard.py`)

SafeStream's promise — *sensitive text never leaves the machine* — is made
**enforceable**, not merely documented. `install()` monkeypatches
`socket.socket.connect`/`connect_ex` so any attempt to open a **non-loopback**
connection raises `NetworkAccessError` before any byte is sent. Loopback
(`127.0.0.0/8`, `::1`, IPv4-mapped loopback) and AF_UNIX sockets are allowed.

- **Not installed on import** — importing the library never changes global socket
  behaviour.
- The **CLI installs it by default** (opt out with `--allow-network`); library
  users call `install()` or use the `netguard.enforced()` context manager.
- Idempotent install/uninstall; each scheduler worker installs its own guard.

This is defense-in-depth against an accidental exfiltration path (e.g. a
misbehaving plugin or NER model download), not a substitute for OS-level
sandboxing.

### 7.2 Other posture

- **No runtime third-party deps in the core** — smaller attack surface; the
  Docker image ships the core only and runs as an unprivileged user.
- **Plugin isolation** — plugin load failures are swallowed so a broken
  third-party tier cannot crash the pipeline. (Trust note: plugins run in-process
  and are as trusted as any installed package.)
- **Pseudonymization is one-way** — HMAC-SHA256, so redacted output cannot be
  reversed without brute-forcing the original value; determinism enables
  cross-record correlation without revealing values.

---

## 8. Extensibility

### 8.1 Detector protocol

```python
@runtime_checkable
class Detector(Protocol):
    name: str
    def detect(self, text: str) -> list[Detection]: ...
```

Any object matching this shape can be passed via `extra_detectors=` or
registered as a plugin. New `EntityType` values are added to the enum;
per-type redaction and context triggers key off the type.

### 8.2 Plugin entry point

```toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_pkg.detectors:MyDetector"   # Detector instance or zero-arg factory
```

Discovered and instantiated automatically (`load_plugins=True` by default);
disable with `Redactor(load_plugins=False)`.

### 8.3 Configuration

TOML policy files (`config.py`) map `[detection]`, `[redaction]`,
`[redaction.replacements]`, `[custom]`, and `[streaming]` sections onto
`Redactor`/`RedactionPolicy` constructor arguments. CLI flags override the file.

---

## 9. Public interfaces

### 9.1 Python API

```python
from safestream_redactor import Redactor, RedactionPolicy, EntityType

Redactor().redact("email bob@corp.io, ssn: 123-45-6789")
# 'email [REDACTED], ssn: [REDACTED]'

Redactor().redact_file("huge.log", "huge_redacted.log")          # O(1) memory
for chunk in Redactor().redact_stream(iter_of_chunks): ...        # generator
for det in Redactor().detect("card 4111 1111 1111 1111"): ...     # detection only
```

Key `Redactor` parameters: `types`, `policy`, `min_confidence`, `custom_words`,
`custom_patterns`, `use_ner`, `use_entropy`, `extra_detectors`, `load_plugins`,
`chunk_size`, `overlap`.

### 9.2 CLI

Two subcommands — `redact` and `detect` — sharing common flags (`--types`,
`--config`, `--custom-word`, `--custom-regex`, `--min-confidence`, `--ner`,
`--no-entropy`, `--chunk-size`, `--overlap`, `--allow-network`). Input `-` is
stdin, output `-` is stdout; a directory input triggers parallel tree redaction.
`redact` adds `--mode`, `--replace`, `--replace-type`, `--keep-last`,
`--mask-char`, `--hmac-key`, `--workers`. `detect --json` emits one JSON object
per detection with absolute offsets.

---

## 10. Data model

```python
class EntityType(str, Enum):   # email, phone, credit_card, ssn, ipv4, ipv6,
    ...                        # aws_key, github_token, api_key, jwt, private_key,
                               # slack_token, slack_webhook, stripe_key,
                               # google_api_key, sendgrid_key, twilio_key,
                               # npm_token, secret, person, org, loc, custom

@dataclass(slots=True)
class Detection:
    start: int; end: int; text: str
    entity_type: EntityType
    confidence: float
    source: str = "deterministic"       # which tier produced it
    meta: dict[str, str] = {}            # e.g. {"entropy": "4.31", "context": "boosted"}
```

`slots=True` keeps per-detection overhead small — relevant when a dense file
produces many detections per window.

---

## 11. Performance characteristics

- **Memory:** O(1) in input size; bounded by `chunk_size + overlap` + largest
  single detection. Proven to stay < 16 MB on a 1 GB file.
- **Throughput:** ~3.13 MB/s on a realistic/adversarial corpus (README
  benchmark), ~50× faster than Presidio's pattern path (0.06 MB/s) on the same
  input, because detection is a bounded set of compiled regexes + cheap
  validators rather than a heavyweight NLP pipeline.
- **Accuracy (README benchmarks):** structured-PII F1 = 1.000; adversarial
  precision = 0.999 / recall = 1.000 while Presidio's phone recognizer collapses
  to P = 0.649 under the same distractors; credential recall 9/9 vs Presidio 0/9.
- Caveat: gold entities in the benchmark use standard formats SafeStream targets;
  free-form prose names/locations require the NER extra.

---

## 12. Testing, tooling & release

- **Test suite** (`tests/`): redaction correctness, streaming/boundary behavior,
  each detector, overlap resolution, config, CLI, scheduler, netguard, and the
  memory proof (marked `memory`, excluded from the default run).
- **CI** (`.github/workflows/ci.yml`): `ruff check` + `ruff format --check` +
  `mypy --strict` (lint job) and `pytest` across Python 3.10–3.13 plus a 64 MB
  memory-proof variant (test matrix).
- **Typing:** strict mypy over `src`; ships `py.typed`. Only the optional spaCy
  and the `tomli` backport are exempted from import typing.
- **Packaging:** hatchling build; core has effectively zero runtime deps
  (`tomli` only on Python < 3.11). Optional extras: `ner`, `dev`, `bench`.
- **Release:** `publish.yml` publishes to PyPI via Trusted Publishing (OIDC) on
  GitHub release; TestPyPI dry-run via manual dispatch.
- **Docker:** multi-stage build; runtime image installs the core wheel only and
  runs as UID 10001.

---

## 13. Design trade-offs & rationale

| Decision | Rationale | Trade-off |
| --- | --- | --- |
| Chunked streaming with overlap | Bounded memory on unbounded input; boundary-safe. | Entities longer than `overlap` (default 4 KB) could in principle split — tune `--overlap` for exotic inputs. |
| Regex + validators over an NLP model for the core | Fast, deterministic, dependency-free, high precision. | Misses free-form names/locations without the NER extra. |
| Confidence thresholds + contextual scoring | Lets ambiguous shapes (bare phone/SSN) depend on nearby cues, cutting false positives. | Tuning is heuristic; unusual phrasing can miss a boost. |
| Entropy tier on by default | Catches undocumented secrets pattern tools miss. | Rare high-entropy non-secrets (e.g. long hashes) can trip it — disable with `--no-entropy`. |
| Per-file (not intra-file) parallelism | Each file is already O(1) memory; simple, robust scaling. | A single enormous file is single-threaded. |
| Offline guard via socket monkeypatch | Enforceable privacy with no external sandbox. | Process-wide and Python-level only; not a kernel-level guarantee. |
| One-way HMAC pseudonyms | Deterministic correlation without reversibility. | No de-tokenization; needs a managed `hmac_key`. |

---

## 14. Future directions

- Configurable overlap-overflow handling for entities exceeding `overlap`.
- Async / non-blocking stream API for pipelines.
- Additional credential signatures and locale-aware PII (non-US phone/ID formats).
- Optional structured (JSON/CSV-aware) mode that redacts by field.
- Sandboxed / out-of-process plugin execution for untrusted detectors.
