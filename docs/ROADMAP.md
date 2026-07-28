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

## Phase 2 — Performance & assurance (next)

- **Single-pass anchored prefilter**: most tier-1 patterns have literal anchors
  (`AKIA`, `eyJ`, `xox`, `-----BEGIN`, `@`); one combined scan can skip windows with
  no anchors at all. Target: 3× throughput on secret-sparse logs. Risk: must be
  provably equivalent — gate with a differential fuzz test against the naive path.
- **Property-based testing**: Hypothesis generators for the streaming-equals-whole-text
  invariant and overlap resolution; this is the cheapest way to find boundary bugs
  the hand-written cases miss.
- **Coverage gate + benchmark tracking in CI**: prevent silent regression of either
  correctness coverage or throughput.
- **Container publishing**: GHCR multi-arch images with SBOM + provenance
  attestation on release.

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
- Pre-commit hook package and GitHub Action wrapping the Phase 1 CI gate.

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
