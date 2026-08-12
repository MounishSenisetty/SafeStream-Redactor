# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Independent real-world accuracy evaluation (`benchmarks/eval_dual.py`): scores the
  deterministic core against the externally-authored Microsoft `presidio-research`
  corpus (fetched on demand), kept strictly separate from the synthetic
  false-positive-resistance fixture. Establishes a reproducible real recall number
  (micro F1 0.885 → 0.907 after the phone improvements below). See
  `docs/adr/0003-independent-accuracy-evaluation.md`.
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

- Phone detection recall improved on real-world formats without any precision loss
  (measured 0.446 → 0.565 on the independent corpus, precision held at 1.000): a
  dedicated NANP `NNN-NNN-NNNN` pattern (dash or dot) that fires without a cue word,
  and support for trailing extensions (`x4587`, `ext. 12`). Cue-less bare numbers stay
  context-gated — promoting them was measured to trade precision for recall on real
  data (0.77 precision, 21 false positives) at flat F1, so it was rejected.
- `credit_card` detection uses a cheaper shape regex + Luhn validator
  (`\d(?:[ -]?\d){12,18}`), ~1.5× faster on card-shaped runs with byte-identical
  matches (differential test enforces).
- Evaluated and rejected a compiled RE2/Hyperscan detection backend on measured
  evidence (not a fit for this pattern set — the accelerable patterns are already
  prefiltered to near-zero on real data, and the real bottlenecks are RE2-incompatible
  or slower under a correctness-preserving integration); documented in
  `docs/adr/0002-no-compiled-regex-backend.md`.
- Deterministic-tier patterns are prefiltered by guaranteed anchor literals: windows
  that cannot contain a match skip the regex entirely (~25× faster on digit-free
  prose, ~1.7× on digit-heavy logs, identical output — enforced by a differential
  test).
- The IPv4 pattern now uses a cheap shape regex plus an `ipv4_ok` validator instead of
  an inline octet alternation, cutting the IPv4 scan roughly in half on IP-dense text.
  A differential test pins the shape+validator combination to exactly the matches the
  old alternation accepted (including rejection of leading-zero octets like `01`).

### Fixed

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
