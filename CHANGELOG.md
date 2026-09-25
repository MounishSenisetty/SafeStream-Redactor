# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Compound-secret tier** (`detectors/entropy.py`, `CompoundSecretDetector`; on
  by default with the entropy tier). Closes the documented cause-#4 gap
  (`benchmarks/redactionbench/AUDIT.md`): a high-entropy secret carrying an
  *embedded strong special* (`! # $ % ^ & * ~`) — e.g. `devPass_pP0p18yO3n!vT8wZ`
  — that the base64 entropy candidate splits on and misses entirely. It fires
  only on a whitespace-free run whose strong special sits *between* two
  alphanumerics, with character-class diversity and an entropy floor, so URLs,
  hosts, e-mail addresses, file paths, and base64/hex blobs cannot trip it. Span
  length is bounded to `MAX_SPAN`, so the streaming/parallel equivalence
  guarantees and the audited locality constants are unchanged. Measured on
  RedactionBench (200 docs, streaming): mandatory recall 0.691 → 0.708, character
  precision 0.7525 → 0.7543 (up), no-mandatory-leak docs 0.125 → 0.135, with **0**
  new false positives on the 55-doc benign public-prose set.

- **Optional local ONNX NER tier** (`Redactor(use_onnx=True, ...)`, CLI `--onnx`,
  the `pip install safestream-redactor[onnx]` extra): an on-device
  token-classification model (BIO/IOB2) for the PERSON / ORG / LOC entities
  deterministic rules cannot catch — the same niche as the spaCy tier, but via a
  portable ONNX model run through `onnxruntime` with **no data egress** (CPU
  provider only; verified under the offline network guard). `onnxruntime`/`numpy`
  are imported lazily so the base install stays pure-Python. Three seams
  (tokenizer / inference backend / pure-Python BIO decoder) keep the logic
  testable without a model and let a Hugging Face tokenizer or custom runner plug
  in; it declares `StreamingRequirements` and pickles its config for the parallel
  scheduler, like the spaCy tier. Bring your own `.onnx` model + vocab — no model
  is bundled. See `docs/DETECTORS.md`.

- **Optional native (Rust) detection core** (`Redactor(backend="native")`, and the
  `pip install safestream-redactor[native]` extra): a compiled, **byte-identical**
  accelerator for the deterministic tier's finite-automaton patterns (12 credential
  patterns + SSN/IPv4/IPv6), run behind the existing detector seam. The base install
  stays pure-Python and dependency-free; `backend="python"` remains the default and
  the oracle, and `backend="native"`/`"auto"` fall back to Python when the extension
  is absent. Output is proven identical to the Python tier (differential + Hypothesis
  gate, including Unicode-digit parity); a runtime spec-guard falls back to Python if
  a version-skewed wheel is paired. Built and published as separate abi3 wheels by
  `.github/workflows/native-wheels.yml`. Measured whole-pipeline redaction gain
  1.4–1.7× (Amdahl-limited by the still-Python entropy/contextual tiers); see
  `docs/NATIVE_CORE.md`. `credit_card`/`phone` (evaluated on `fancy-regex`) and the
  entropy tier were measured and deliberately **left in Python** — the doc records
  why.

### Fixed

- **Security: quadratic backtracking (ReDoS) in the default-on labeled-identifier
  tier.** Its separator `\s*[:=#\-.]?\s*` let the regex engine split a whitespace
  run every possible way, so a cue word followed by a long whitespace run cost
  O(n²): `"ssn" + 32K spaces` took ~19 s in one `detect()` call, and the REST API
  and MCP server (which detect over whole request bodies of up to 8 / 4 MiB) could
  be pinned for hours by a single request. The rewritten separator matches the
  same language in O(n) (8 ms for the same input).
- **Security: quadratic EMAIL scan.** `finditer` retried the local part from every
  word boundary of a long `a.a.a.…` run (1.3 s per 32K chars). A linear
  `@`-anchored scanner now yields exactly the matches `finditer` would
  (differential-tested); the pattern source, and so the native spec, is unchanged.
- **Line endings are preserved.** File input used universal newlines, silently
  rewriting `\r\n` and lone `\r` to `\n` in *unredacted* text (and writing
  `os.linesep` on Windows), while stdin preserved them — the same bytes redacted
  to different output by path. All paths now pass line endings through verbatim.
- **`--encoding` is honoured for stdin/stdout**, which previously used the
  locale's encoding regardless of the flag.
- The labeled-identifier tier emitted spans of unbounded length (12,001 chars
  observed) despite declaring `max_span=64` to the overlap sizing; values are now
  bounded to 64 chars, and its cue-distance guard subtracted the value length
  from the gap by mistake.
- The labeled card rule swallowed a trailing space or hyphen, so
  `card 4111 1111 1111 1111 key` became `card [REDACTED]key`; card values now end on a
  digit.
- `mypy` failed whenever the optional native wheel was installed.

- **Audited locality constants corrected and made self-checking**
  (`docs/FORMAL_MODEL.md`, `paper/ftnct09/`, `tests/test_formal_constants.py`).
  The default-on label-anchored identifier cascade reads a 96-character
  cue→value window, so the formal model's hand-traced `C_left = 48` /
  `C_right = 2` were stale for the shipped pipeline. The constants are now derived
  mechanically from the detectors' declared `StreamingRequirements`
  (`C_left = 96`, `C_right = 8`, `L_max = 8192`) and pinned by a regression test
  that fails if any future tier reads wider context, keeping the doc and paper in
  lockstep with the code. The equivalence guarantee is unaffected — the default
  overlap (8192) already dwarfs the corrected constants.

### Performance

- `resolve_overlaps` is O(n log n) (was O(n²)): 20,000 adjacent e-mails went from
  14.9 s to 0.25 s; on ordinary log windows it had been the single largest cost.
- The streaming engine coalesces small input chunks before a detection pass, so
  `redact_stream` over a line iterator no longer rescans the whole window per
  line (0.01 → 1.47 MB/s on ~100-char lines, now on par with 64 KiB chunks).
- CI's hard-corpus benchmark throughput: 0.12 → 1.74 MB/s. Output and
  precision/recall are identical before and after.

### Packaging & container

- Build backend bounded to `hatchling>=1.27,<2` (the PEP 639 metadata used here
  needs 1.27); `[native]` extra bounded to the lockstep `<0.5` series; Python 3.14
  classifier and CI job (the container's interpreter was never tested in CI).
- The sdist now contains only what pip needs (`src/`, `LICENSE`, metadata): 2.5 MB →
  100 KB; the paper PDF, datasets, images, tests and CI files are no longer published.
- The PyPI project page (`src/README_PYPI.md`) is rewritten around installing and using
  the package: every CLI command and its options, entity types, config file, exit codes
  and the Python API. It no longer advertises `pip install '…[native]'`, which fails
  because the native wheel has never been published.
- `publish.yml` now refuses to upload unless the release tag matches `__version__`,
  `twine check --strict` passes, and both the wheel and the sdist install into a clean
  environment and redact correctly. Release steps are documented in `docs/RELEASING.md`.
- Dockerfile: hash-locked build backend, pip-less runtime venv with precompiled
  bytecode (app layer ~11.8 MB → ~1 MB), numeric non-root `USER 10001:10001`,
  base image pinned by digest, bit-reproducible layers with `SOURCE_DATE_EPOCH`,
  allow-list `.dockerignore`. The documented `docker run -v "$PWD":/data` failed
  with *Permission denied* on Linux hosts; docs now pass `--user`.
- The Docker workflow smoke-tests the image before pushing; the native-wheel
  workflow now runs the byte-identity tests against the built wheel and gates
  publishing on them (they previously never ran in CI).

## [0.4.0] - 2026-08-30

### Added

- **Explicit memory-budget admission control** (`safestream_redactor.memory_budget`,
  `--memory-limit`): run within a stated application memory budget (e.g.
  `--memory-limit 32MB`). The engine estimates the per-worker streaming working
  set, derives the worker count that keeps the aggregate under the budget, and
  **fails closed** with a structured `ResourceExhaustionError` (CLI exit code 3)
  rather than silently over-allocating or loading the whole file. Documented,
  with an honest working-set-vs-RSS distinction, in `docs/MEMORY_ARCHITECTURE.md`.
- **Detector streaming-requirements metadata** (`StreamingRequirements`): each
  detector declares its longest span and the left/right context it reads, and
  the engine derives the required overlap from the detectors actually in use
  (`engine.required_overlap`, `Redactor.min_safe_overlap`) instead of a single
  global constant. Shrinking the overlap below what the active tiers need now
  logs a boundary-coverage warning.
- **Local MCP server** (`safestream mcp-serve`, `safestream_redactor.mcp_server`):
  a stdlib-only, offline stdio JSON-RPC 2.0 Model Context Protocol server exposing
  `scan`, `redact`, `explain_detection`, `detectors`, and `health` tools.
  `scan`/`explain_detection` return finding metadata only — type, location,
  confidence, severity, detector — and **never the matched secret**. Documented
  in `docs/MCP.md`.
- **SARIF 2.1.0 output** for the CI gate (`detect --sarif`): content-free findings
  (severity-mapped levels, security-severity scores) for GitHub code scanning.
- **Pre-commit hook and GitHub Action** wrapping the secret gate
  (`.pre-commit-hooks.yaml`, `action.yml`); `detect` now accepts multiple input
  files so it works as a staged-file gate.
- **Severity classification** (`safestream_redactor.severity`): a shared,
  content-free four-level scale used by MCP and SARIF.
- **`.claude/` developer workflow**: an `add-a-detector` skill, a `detector-author`
  agent, and an `add-detector` command that walk a contributor through pattern
  design, boundary safety, hard-negative fixtures, and the CI gates.
- **Adversarial boundary test suite** (`tests/test_boundary_adversarial.py`):
  representative secrets split at every byte position and many chunk sizes,
  secret-at-byte-0 / secret-at-EOF, multi-entity boundary crossings, a PEM key
  split across dozens of chunks, multibyte-Unicode splits, and the documented
  entity-longer-than-overlap limitation.

## [0.3.0] - 2026-08-16

### Added

- Complete project walkthrough (`docs/PROJECT_OVERVIEW.md`): what the project is, the
  layered architecture, and a per-file table of what every module does and why it exists.
- Measured benchmark results and an honest competitor comparison under `research/`:
  accuracy/throughput on the clean and adversarial synthetic corpora and a constant-memory
  scaling curve (all with full environment metadata in `research/results/raw/`), plus a
  documented capability matrix vs. 10 existing systems (Presidio, Philter, Piiranha,
  GLiNER, Grepture, Private AI, AWS Comprehend, Google DLP, Microsoft Purview, Tonic AI)
  with a `benchmark-report.md` and `competitive-analysis.md`. Competitor rows are labelled
  Documented (not benchmarked); only SafeStream's numbers are Measured.
- Optional local REST API (`safestream_redactor.api`, `safestream serve`): a
  standard-library-only (`http.server`) transport adapter around the same
  `Redactor` — no new runtime dependency. Routes: `GET /health`, `GET /version`,
  `GET /detectors`, `POST /redact`, `POST /scan`. Binds to loopback by default,
  never logs request bodies, rejects oversized bodies with `413`, and keeps
  `/scan` content-free (offsets + types, never the matched text). Documented in
  `docs/rest-api.md`. Added `Redactor.detector_names` for introspection.
- Architecture diagram sources organised under `docs/architecture/` (Mermaid +
  PlantUML), recreated from the system-design document and validated against the
  implementation. The class model was corrected to match the real `EntityType`
  enum, `Detection` fields, and `RedactionStats`; a REST API diagram was added.
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
