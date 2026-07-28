# Changelog

Notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

### Changed

- Deterministic-tier patterns are prefiltered by guaranteed anchor literals: windows
  that cannot contain a match skip the regex entirely (~25× faster on digit-free
  prose, ~1.7× on digit-heavy logs, identical output — enforced by a differential
  test).
- `redact_file` writes atomically (temp file + rename): a crash can no longer leave a
  partially redacted file that looks complete, and previous output survives failures.
  Redacting a file onto itself is now rejected with an error.

## [0.1.0] - 2026-07-25

### Added

- Initial release: constant-memory streaming redaction engine with overlap windows,
  deterministic regex+validator tier, high-entropy secret tier, optional spaCy NER
  tier, contextual boost/suppress scoring, redaction policies (replace, mask,
  HMAC pseudonymize, per-type overrides), TOML policy files, CLI with stdin/stdout
  streaming, RAM-aware parallel directory scheduler, offline network guard, detector
  plugin entry points, Docker image, and reproducible benchmarks against Presidio.
