# Improvement Roadmap

This roadmap turns every gap in [AUDIT.md](AUDIT.md) into a prioritised, incremental
plan. Ordering principle: **fail-closed correctness first, operator trust second,
performance third, research features last.** Every item preserves existing behaviour;
nothing working is removed.

For each item: why it is needed, the business value, the technical value,
implementation steps, and risks/trade-offs.

## Guiding decision: what this project deliberately is *not*

An honest enterprise redesign has to say what it will not do. The obvious
"production-grade" template — REST microservice, database, auth, rate limiting,
Kubernetes — was evaluated and **rejected for the core**, because it inverts the
product's strongest property:

- The differentiator is an *enforced* guarantee that sensitive text never leaves the
  machine (`netguard`). A hosted redaction service is the exact opposite: it requires
  shipping the sensitive text over the network before it is redacted.
- The enterprise deployment model for a DLP primitive is therefore **embedding**:
  a zero-dependency library, a composable CLI for pipelines (`tail -f | safestream`),
  a non-root container for batch jobs, and a CI gate for repositories. Auth, audit,
  and rate limiting belong to the systems that embed it; *evidence* (tamper-evident
  run reports) is what this tool must provide to those systems.
- A separately packaged, explicitly opt-in service wrapper remains a Phase 4 option
  for teams that accept the trade-off — it must never be the default path.

This is the difference between production-grade and production-theatre: complexity is
added only where it strengthens the actual guarantee.

## Phase 1 — Production trust (implemented in this change set)

### 1.1 Structured logging & observable plugin loading

- **Why**: `load_plugins` currently swallows all failures; a vanished detector tier
  means silently reduced redaction — a fail-open defect. The library also emits no
  operational signal at all.
- **Business value**: operators can prove which tiers ran; a broken plugin becomes a
  visible warning instead of a silent coverage loss.
- **Technical value**: standard `logging` integration (null handler by default) gives
  embedders their own routing/formatting for free.
- **Steps**: add module loggers; warn with plugin name + exception on load failure;
  debug-log tier composition; never log matched text (content must not reach logs).
- **Risks**: none — a `NullHandler` keeps the library silent unless the host opts in.

### 1.2 Credential coverage: connection-string passwords, OpenAI/Anthropic keys

- **Why**: passwords embedded in URLs (`postgres://user:secret@host`) are among the
  most common real leaks in logs; LLM API keys are the fastest-growing secret class.
  Neither is currently detected as a named type.
- **Business value**: closes the highest-frequency real-world leak classes.
- **Technical value**: both formats are anchored and high-precision (fits the
  validator-backed tier-1 philosophy; no recall/precision trade-off).
- **Steps**: new `url_credentials`, `openai_key`, `anthropic_key` entity types +
  patterns + tests, including adversarial negatives.
- **Risks**: pattern collisions (e.g. Stripe `sk_live_` vs OpenAI `sk-`); mitigated by
  anchored prefixes and overlap resolution (most-specific wins), covered by tests.

### 1.3 Run reports & statistics (audit evidence, never content)

- **Why**: a redaction run currently ends with no evidence. Compliance workflows
  (GDPR/CCPA/SOC 2) need to *file* what was done: counts per entity type, files,
  bytes, duration — explicitly never the matched text.
- **Business value**: turns each run into an auditable artefact; this is the
  enterprise "audit logging" requirement implemented in the only way that does not
  weaken the privacy guarantee.
- **Technical value**: `redact_file` finally returns actionable data; the scheduler
  aggregates per-file stats; one report schema shared by CLI and API.
- **Steps**: `RedactionStats` counters threaded through file/stream/tree paths;
  `--stats` (human summary to stderr) and `--report FILE` (JSON) on the CLI.
- **Risks**: report must stay content-free by construction — enforced by containing
  only integers/type names in the schema, and tested.

### 1.4 CI secret gate: `detect --fail-on-detect`

- **Why**: the detector is already a better secret scanner than most CI gates; it only
  lacks a non-zero exit signal.
- **Business value**: one flag makes SafeStream a pre-commit/CI guard that blocks
  secrets *before* they land in a repository or log pipeline.
- **Technical value**: trivially composable (`safestream detect build.log
  --fail-on-detect`), no new subcommand surface.
- **Steps**: add flag; exit 1 when any detection survives filtering; test both paths.
- **Risks**: none; default behaviour unchanged.

### 1.5 Durable output: atomic writes & self-overwrite guard

- **Why**: a crash mid-`redact_file` leaves a truncated file that *looks* redacted —
  a downstream consumer shipping it is a data-leak incident. Writing output over the
  input destroys the source on failure.
- **Business value**: eliminates a silent-partial-output incident class entirely.
- **Technical value**: temp-file-in-target-dir + `os.replace` gives atomicity on
  POSIX and Windows; explicit error when input and output resolve to the same file.
- **Steps**: rework `redact_file` write path; clean up temp file on failure; tests
  for crash simulation and same-path rejection.
- **Risks**: `os.replace` semantics differ across filesystems (e.g. cross-device) —
  avoided by creating the temp file in the destination directory.

### 1.6 Supply-chain & CI hardening

- **Why**: no dependency auditing, no automated updates, no vulnerability disclosure
  channel, single-OS CI despite OS-sensitive code (sockets, `/proc`, process pools).
- **Business value**: table stakes for enterprise adoption reviews.
- **Technical value**: `pip-audit` job, Dependabot for actions + pip, macOS/Windows
  test legs, least-privilege workflow permissions, `SECURITY.md`, `CHANGELOG.md`.
- **Risks**: Windows leg may surface real platform bugs — that is the point; kept
  non-blocking only if flaky for environmental reasons.

## Phase 2 — Performance & assurance (implemented)

- **Anchored prefilter** *(done)*: every tier-1 pattern declares literals any match
  must contain; windows without them skip the regex. Measured ~25× on digit-free
  prose and ~1.7× on digit-heavy logs, gated by a differential test proving output
  identity with the prefilter disabled.
- **Property-based testing** *(done)*: Hypothesis generators cover the
  streaming-equals-whole-text invariant, segment reassembly/offsets, and the overlap
  resolution contract (sorted, non-overlapping, maximal, idempotent), derandomized
  for reproducible CI.
- **Coverage gate + detection-quality gate in CI** *(done)*: 95% coverage floor;
  benchmark job regenerates the seeded corpora and fails below fixed
  precision/recall floors.
- **Container publishing** *(done)*: GHCR multi-arch images with SBOM + provenance
  attestation on release.

## Phase 2.5 — Credibility & honesty fixes (implemented)

Prompted by an external-review pass; these correct claims and close fail-open gaps
rather than add features.

- **Honest benchmarking** *(done)*: `benchmarks/evaluate.py` scores against independent
  labeled corpora; the synthetic benchmark is relabeled a regression fixture (its recall
  was near-circular). Throughput is stated as a known limitation, not a strength.
- **Truthful security claims** *(done)*: the offline guard is documented as best-effort
  in-process prevention, not a hard boundary.
- **Pseudonymization** *(done)*: widened to 64-bit configurable tokens; documented as
  reversible-by-key-holder, not anonymization.
- **Fail-closed config** *(done)*: unknown TOML keys/sections are errors, not silent
  default fallback.
- **ReDoS bound** *(done)*: the private-key body is length-capped against pathological
  scans.

Also implemented since:

- **Encoding safety** *(done)*: undecodable bytes are counted, reported, and warned
  about (unscanned content is a coverage risk); `--encoding` reads non-UTF-8 sources.
- **NER-in-scheduler** *(done)*: the NER detector pickles as config and reloads its
  model per worker, so bulk redaction no longer serializes a spaCy model over IPC; the
  tier now has real test coverage via an injected fake spaCy.
- **Operability** *(done)*: `init-config` emits a schema-validated starter policy;
  directory runs report per-file progress; the stdin→file path writes atomically.

- **Intra-file parallelism** *(done)*: a single large file is split into
  character-aligned byte ranges and redacted across processes, with output
  byte-identical to the sequential pass for entities within the overlap guarantee
  (measured ~3.7× on 4 cores). A seam cross-check makes character loss/duplication at
  a range boundary structurally impossible — any disagreement falls back to the
  sequential pass. Design and equivalence argument in
  [docs/adr/0001-intra-file-parallelism.md](adr/0001-intra-file-parallelism.md).

Still open (highest-value next):

- **Throughput constant factor** — parallelism now uses idle cores, but each core
  still runs the Python regex tiers at ~3 MB/s. A drop-in Vectorscan/re2 backend was
  **prototyped, measured, and not adopted**: re2's ASCII-only `\b`/`\w`/`\d` change
  detection output on Unicode text (under-detecting), and it gives no end-to-end
  speedup because the anchor prefilter already captures its advantage while the
  throughput-dominating PII patterns (SSN, card, IPv4, phone, IPv6) use lookaround re2
  cannot compile — see [docs/PERFORMANCE_BACKENDS.md](PERFORMANCE_BACKENDS.md). The
  real prerequisite is therefore a **semantics-preserving pattern rewrite**: recast the
  lookaround PII patterns as lookaround-free candidate regexes (boundary logic moved
  into their validators, as several tiers already do) with Unicode-consistent boundary
  classes; only then can a compiled backend match byte-for-byte and help. That rewrite,
  not the backend itself, is the open work. (Zero-copy input I/O — `mmap`/`preadv`/
  `splice` — was likewise evaluated and **not adopted**: input I/O is already
  ~2600–3800× faster than detection, so it is not on the critical path; see
  [docs/ZERO_COPY.md](ZERO_COPY.md). Both are worth revisiting only *after* detection
  itself is fast enough for the surrounding layers to matter.)

## Phase 3 — Research-grade detection

- **Format-aware context**: recognise JSON/CSV/logfmt structure so field *names*
  (`"ssn":`, `password=`) feed the contextual tier with near-perfect precision.
- **Calibrated confidence**: replace hand-set per-pattern confidences with scores
  calibrated on a labelled corpus; publish the calibration methodology.
- **ONNX NER option**: a transformer NER tier without the spaCy dependency chain, with
  cross-chunk-boundary accuracy tests; keeps the offline guarantee (local inference).
- **Public evaluation harness**: reproducible comparisons on public PII corpora, so
  benchmark claims graduate from "our synthetic data" to independent evidence.

## Phase 4 — Optional ecosystem (explicitly opt-in)

- Separate `safestream-server` package (REST + auth + rate limiting) for teams that
  accept in-network redaction; the core never depends on it.
- Pre-commit hook package and GitHub Action wrapping the Phase 1 CI gate *(done, 0.4.0)*.

## Phase 5 — Resource governance, agent integration, and CI surface (0.4.0)

Implemented in the 0.4.0 change set; each item is real and tested, and none
weakens the local-first guarantee.

- **Explicit memory budget** *(done)*: `--memory-limit` admission control that
  estimates the streaming working set, derives a budget-bounded worker count, and
  fails closed with a structured `ResourceExhaustionError` (exit 3). The budget
  bounds the application working set, not process RSS — a distinction the docs
  state plainly rather than hide. See `docs/MEMORY_ARCHITECTURE.md`.
- **Detector-declared streaming context** *(done)*: `StreamingRequirements`
  replaces the single global overlap constant with a value the engine derives
  from the detectors in use; shrinking the overlap below the requirement warns.
- **Local MCP server** *(done)*: `safestream mcp-serve`, offline stdio JSON-RPC,
  metadata-only `scan`/`explain_detection` (the secret never crosses the tool
  boundary). See `docs/MCP.md`.
- **CI surface** *(done)*: SARIF 2.1.0 output, a pre-commit hook, and a GitHub
  Action; `detect` accepts many files as a staged-file gate. See `docs/CI_CD.md`.
- **AI developer workflow** *(done)*: `.claude/` add-a-detector skill, agent, and
  command.

### Deliberately deferred (with justification)

- **Rust/native core**: evaluated and deferred. The bounded-memory invariant is
  already met in pure Python (the working set is `O(chunk+overlap)`, not `O(input)`),
  so a native core buys *throughput*, not memory safety. The obvious form — a
  Vectorscan/re2 backend behind the `Detector` seam — was prototyped and measured, and
  it does not work as a drop-in: it changes output on Unicode and gives no end-to-end
  speedup (see [PERFORMANCE_BACKENDS.md](PERFORMANCE_BACKENDS.md) and the "throughput
  constant factor" note above). A native core only pays off *after* the
  semantics-preserving pattern rewrite described there, and even then must clear its
  own byte-identity + benchmark gate. Introducing PyO3/maturin, cross-platform wheels,
  and a native build matrix for a marketing bullet would be production-theatre; it is
  scoped as its own project.
- **ONNX/local-LLM detector**: the plugin architecture and streaming-requirements
  metadata make this a drop-in `Detector`, but shipping it means shipping (or
  fetching) a model with integrity verification and calibration — work that must
  not degrade into a fake/stub detector. Tracked as Phase 3 "ONNX NER option".

## Self-critique iterations applied to this plan

1. *Draft 1* put a REST API in Phase 1 as the "enterprise" feature. Rejected: it
   contradicts the enforced-offline differentiator (see guiding decision above).
2. *Draft 2* proposed per-detection audit logs including matched text for
   traceability. Rejected: an audit log that contains the secrets is itself a leak;
   the report schema is now content-free by construction.
3. *Draft 3* proposed parallelising a single file by splitting at chunk boundaries.
   Deferred to Phase 2+: it breaks left-context determinism (contextual scoring would
   differ from whole-text mode near split points) — needs the prefilter design first,
   plus a correctness proof at split seams.
4. *Draft 4* included ~20 new credential patterns. Cut to the three with strong
   anchors and real-world frequency; each weak pattern added is a precision tax on
   every user (the adversarial benchmark exists precisely to keep this honest).
