# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Conflict-only arbitration tier (`safestream_redactor.arbitration`): a resolver consulted
  **only** when detectors disagree — overlapping candidates with near-equal confidence, a
  detection at the `min_confidence` threshold, or a contextually-suppressed match — so it
  stays rare and adds latency only where it changes the decision. Two arbiters ship:
  `RuleArbiter`, a deterministic, fully-offline default that reads only candidate-local
  fields and therefore preserves the streaming/parallel equivalence guarantees; and
  `LLMArbiter`, which delegates the ruling to any injected `str -> str` language-model
  client (the package hard-codes no vendor and pulls in no SDK). Enable via
  `Redactor(arbiter=…)` or a `[arbitration] arbiter = "rule"` config section. Enabling an
  `LLMArbiter` with a hosted model relaxes the offline and equivalence guarantees, so it is
  opt-in and never the default; a client error falls back to the deterministic arbiter.
- Formal model document (`docs/FORMAL_MODEL.md`): definitions, the two locality
  assumptions with their audited constants, and Theorems 1–3 (streaming equivalence,
  parallel byte-identity with safe fallback, constant memory) with proofs mapped to the
  code that discharges each obligation.
- Learned confidence calibration (`safestream_redactor.calibration.Calibrator`): a
  dependency-free logistic model that maps a detection's local features to a calibrated
  probability, so `min_confidence` acts on comparable probabilities across tiers. Wire it
  in via `Redactor(calibrator=…)` or a `[calibration] model = "…"` config section; it is
  a per-detection function of local features, so it preserves the streaming/parallel
  equivalence guarantees. Train and evaluate one with `benchmarks/calibrate.py`
  (Brier score, expected calibration error, and a per-tier ablation).
- Evaluation harness upgrades (`benchmarks/evaluate.py`): 95% bootstrap confidence
  intervals (`--bootstrap`), a paired-bootstrap significance test between two systems
  (`--compare`), baseline adapters behind one common interface
  (`--system {safestream,regex,presidio,scrubadub,gitleaks}`), CoNLL-2003 and
  Presidio-research-dataset loaders (`--conll` / `--presidio-json`), and per-type
  error analysis (`--errors`).
- Scaling-proof scripts: `benchmarks/scale_memory.py` (peak-memory-vs-size curve for
  Theorem 3) and `benchmarks/parallel_speedup.py` (speedup vs. worker count with a
  byte-identity assertion at every count for Theorem 2).

### Changed

- **Default streaming overlap raised from 4096 to 8192 characters.** Every detector now
  emits spans no longer than the overlap, so the premise of the streaming-equivalence
  theorem (`overlap >= L_max`) holds unconditionally at the default configuration. The
  private-key pattern's key-type fields and body are bounded so its widest possible span
  is exactly 8192, and the entropy candidate is capped at 8192 (a longer high-entropy run
  is redacted as consecutive ≤8192 spans rather than one unbounded span). Detection output
  is unchanged for every run up to the overlap; a differential test pins this.

## [0.2.0] - 2026-08-15

### Added

- `aws_secret` detection: a precise, high-confidence label pattern for the 40-char AWS
  Secret Access Key behind an `aws … secret … key` cue. Only the secret value is
  redacted (the label stays readable), and the specific label beats the weaker
  entropy-tier catch it previously relied on.
- Ready-to-use example policy (`examples/policy.toml`): enables the NER tier and ships
  label-anchored custom patterns for identifiers with no universal format — passport,
  driver licence, bank account, routing number, employee ID, Slack user ID, and date of
  birth — each documented inline. Run with `--config examples/policy.toml`.
- README "Detection accuracy & limitations" section: why 100% recall+precision is
  unattainable for free-text PII, why files saturated with `test`/`sample`/`example`
  markers under-detect (contextual suppression, by design), and the three recall levers
  (lower `min_confidence`, enable NER, add custom patterns).
- Intra-file parallel redaction (`safestream_redactor.parallel`): a single large
  file is split into character-aligned byte ranges and redacted across processes,
  with output **byte-identical** to the sequential pass for entities within the
  overlap guarantee. Enable it with `Redactor.redact_file(..., workers=N)` or
  `safestream redact big.log -o out.log --workers N`. A seam cross-check makes
  character loss or duplication at a range boundary structurally impossible: any
  disagreement transparently falls back to the sequential pass, as do small files
  and encodings that cannot be split safely. Measured ~3.7× on 4 cores; see
  `docs/adr/0001-intra-file-parallelism.md` for the design and equivalence
  argument.
- `url_credentials` detection: passwords embedded in connection-string URLs
  (`postgres://user:PASS@host`); only the password is redacted so the DSN stays
  readable.
- `openai_key` and `anthropic_key` credential detection.
- Run statistics and reports: `Redactor.redact_file` returns `RedactionStats`
  (per-type counts, characters in/out), `redact_stream` can accumulate the same, and
  the scheduler carries per-file counts. CLI: `redact --stats` prints a summary,
  `redact --report FILE` writes a JSON run report containing only counts and sizes —
  never matched text.
- `detect --fail-on-detect`: exit status 1 when anything is detected, for CI and
  pre-commit secret gates.
- Structured logging throughout (null handler by default); detector plugins that fail
  to load now emit a warning instead of disappearing silently.
- Repository audit (`docs/AUDIT.md`) and improvement roadmap (`docs/ROADMAP.md`).
- Security policy (`SECURITY.md`) with an explicit threat model, Dependabot updates,
  a `pip-audit` CI job, and macOS/Windows CI legs.

- Property-based tests (Hypothesis) for the streaming-equals-whole-text invariant and
  overlap-resolution contract; a 95% coverage gate; and a CI job that regenerates the
  seeded benchmark corpora and fails if precision/recall fall below fixed floors.
- Container publishing: releases build multi-arch (amd64/arm64) images to GHCR with an
  SBOM and provenance attestations; the Dockerfile carries OCI metadata labels.

- `benchmarks/evaluate.py`: an accuracy harness that scores against an independent,
  externally-labeled corpus (per-type + micro-averaged P/R/F1, label mapping),
  separating real accuracy measurement from the synthetic regression fixture.
- `--encoding` flag for non-UTF-8 sources; a new `init-config` command that writes a
  documented, schema-validated starter policy; and per-file progress reporting for
  directory redaction (live on an interactive terminal, via a `progress` callback on
  `redact_tree`).

### Security

- Corrected the offline-guard claims: it is best-effort in-process egress prevention,
  not a boundary that makes data "provably never leave the machine" (README, module
  docstring, and audit updated to match `SECURITY.md`).
- Pseudonymization token widened from 40 to 64 bits (configurable 8–64) to avoid
  collisions on large corpora, with explicit documentation that deterministic keyed
  pseudonyms are re-identifiable by the key holder — not anonymization.
- Policy config now fails closed: an unknown TOML section or key is rejected with a
  suggestion instead of silently falling back to defaults (which could ship unredacted
  output).
- The private-key pattern body is length-bounded, so a `BEGIN`-without-`END` marker
  followed by a large base64 run can no longer trigger a pathological long scan.
- Undecodable input bytes are surfaced: replacement characters are counted in the run
  report and the CLI warns, since bytes replaced with U+FFFD are content no detector
  scanned. Output writes for the stdin→file path are now atomic too.

### Changed

- Deterministic-tier patterns are prefiltered by guaranteed anchor literals: windows
  that cannot contain a match skip the regex entirely (~25× faster on digit-free
  prose, ~1.7× on digit-heavy logs, identical output — enforced by a differential
  test).
- The IPv4 pattern now uses a cheap shape regex plus an `ipv4_ok` validator instead of
  an inline octet alternation, cutting the IPv4 scan roughly in half on IP-dense text.
  A differential test pins the shape+validator combination to exactly the matches the
  old alternation accepted (including rejection of leading-zero octets like `01`).

### Fixed

- Labelled passwords containing special characters (`@ ! # $ % ^ & *`) were truncated at
  the first special char, dropping them below the 12-char minimum so they went
  undetected. The generic `key/secret/token/password = value` value class now includes
  common password specials, so a value like `P@ssw0rd-123!` is captured whole. Safe
  because the match is still gated by an explicit label followed by `:` or `=`.
- The in-process (single-worker) path of `redact_tree` installed the offline network
  guard in the **caller's** process and never removed it, silently patching a library
  user's sockets for the rest of the process. The guard is now scoped to the run and
  a pre-existing guard installed by the caller is left untouched.
- `redact_file` writes atomically (temp file + rename): a crash can no longer leave a
  partially redacted file that looks complete, and previous output survives failures.
  Redacting a file onto itself is now rejected with an error.
- The NER detector pickles as configuration only (model name + confidence) and reloads
  its model in each worker process, so bulk directory redaction with `use_ner=True` no
  longer serializes a large spaCy model across process boundaries.

## [0.1.0] - 2026-07-25

### Added

- Initial release: constant-memory streaming redaction engine with overlap windows,
  deterministic regex+validator tier, high-entropy secret tier, optional spaCy NER
  tier, contextual boost/suppress scoring, redaction policies (replace, mask,
  HMAC pseudonymize, per-type overrides), TOML policy files, CLI with stdin/stdout
  streaming, RAM-aware parallel directory scheduler, offline network guard, detector
  plugin entry points, Docker image, and reproducible benchmarks against Presidio.
