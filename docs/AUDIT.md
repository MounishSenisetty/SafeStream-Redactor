# Repository Audit

A category-by-category assessment of the codebase as of v0.1.0 (commit `cf683d8`).
Each category is scored 1–10 with the reasoning behind the score. The companion
[ROADMAP.md](ROADMAP.md) turns every gap identified here into a concrete, prioritised
plan.

Scope of the audit: every file in `src/`, `tests/`, `benchmarks/`, `.github/`, the
`Dockerfile`, and packaging metadata.

## Summary scorecard

| Category          | Score | One-line verdict |
| ----------------- | :---: | ---------------- |
| Architecture      |  8    | Clean layered pipeline with a real plugin seam; no format-aware detection seam yet |
| Code quality      |  8    | Strict mypy + ruff, slotted dataclasses; CLI mutates `Redactor` internals |
| Performance       |  7    | ~3 MB/s single core; N sequential regex passes per window; no regression tracking |
| Scalability       |  7    | RAM-aware multi-process across files; single large file is single-core |
| Security          |  7    | Offline network guard is genuinely strong; silent plugin failures, non-atomic writes, no dependency auditing |
| Maintainability   |  8    | Small focused modules, good docstrings; config/CLI override logic duplicated |
| Testability       |  8    | 78 fast tests incl. a constant-memory proof; no property-based tests or coverage gate |
| Documentation     |  7    | Excellent README with honest benchmark caveats; no CHANGELOG, security policy, or API reference |
| UI/UX (CLI)       |  7    | Coherent flags, stdin/stdout composability; no run summary, no machine-readable report, no CI gate mode |
| API design        |  8    | Small facade, protocol-based extension; `redact_file` returns nothing actionable |
| Database design   |  N/A  | Deliberately storage-free — statelessness *is* the privacy feature (appropriateness: 9) |
| Deployment        |  8    | Multi-stage non-root Docker, PyPI trusted publishing; no image publishing, SBOM, or signing |
| AI components     |  6    | Optional spaCy NER only; no calibration, no evaluation harness for the NER path |
| Novelty           |  8    | Enforced offline guarantee + constant-memory overlap streaming + credential focus is a real differentiator |

## Detailed findings

### Architecture — 8/10

The pipeline is cleanly layered and each layer is independently testable:

- `engine.py` — pure streaming window algorithm, knows nothing about detectors.
- `detectors/` — four tiers behind a single `Detector` protocol (`base.py`), plus
  entry-point plugin discovery (`registry.py`).
- `entities.py` — shared value types and overlap resolution.
- `policy.py` — redaction rendering, isolated from detection.
- `redactor.py` — thin facade wiring the above.
- `scheduler.py` / `netguard.py` — orthogonal concerns kept out of the core.

The overlap-window design (emit boundary retreats to a detection's start; emitted text
retained as read-only left context so contextual scoring matches whole-text mode) is
the repository's strongest idea and is correctly isolated in one module.

Held back from higher: there is no seam for *format-aware* detection (JSON/CSV/logfmt
field names are powerful context the contextual tier can't currently see), and the CLI
reaches into `Redactor._detectors` to apply config overrides — a layering leak.

### Code quality — 8/10

Strict `mypy --strict` passes over the whole `src` tree, ruff enforces a meaningful
rule set (`B`, `SIM`, `UP`, `RUF`), dataclasses use `slots`, and optional dependencies
are imported lazily so the zero-dependency core claim holds. Docstrings explain *why*
(e.g. the suppress-window rationale in `contextual.py`).

Deductions: `cli.py:_build_redactor` mutates private state (`redactor._detectors[0] = ...`);
`registry.load_plugins` swallows every exception with no diagnostic; two near-identical
override code paths (config-file vs flags) will drift.

### Performance — 7/10

Throughput is ~3.1 MB/s on the adversarial benchmark — 50× Presidio, and adequate for
log pipelines, but the deterministic tier runs ~19 compiled regexes sequentially over
every window, so cost is O(patterns × text). There is no anchored-prefix prefilter, no
combined alternation, and nothing tracks throughput over time, so a regression would
land silently.

### Scalability — 7/10

Across files the story is genuinely good: a process pool sized by both CPU count and
`/proc/meminfo` available RAM, with constant-memory workers, means a directory of any
size redacts safely. Within one very large file, processing is single-core by design
(chunks are sequential because of the rolling context); that is a reasonable trade-off
but is not documented as such, and there is no work-splitting option for the common
"one 100 GB file" case.

### Security — 7/10

Strengths: the `netguard` egress guard is a best-effort, defense-in-depth layer that
reliably stops *accidental* egress by this process and its Python dependencies —
including inside scheduler worker processes — though it is not a hard boundary (a native
syscall, subprocess, or co-resident process bypasses it; see `SECURITY.md`). Docker runs
as a non-root user. Publishing uses
OIDC trusted publishing (no long-lived PyPI tokens). Pattern validators (Luhn, SSN
rules, `ipaddress` parsing) reduce false positives that would otherwise leak *un*redacted.

Gaps that matter in production:

1. **Non-atomic output writes.** `redact_file` writes the destination in place; a crash
   mid-run leaves a partially redacted file that looks complete. A downstream consumer
   of that file has a data-leak incident.
2. **Silent plugin failures.** `load_plugins` drops broken plugins with `except
   Exception: continue` — an operator cannot tell a detector tier silently vanished,
   which again fails *open* (less redaction, not more).
3. **No supply-chain controls**: no dependency audit in CI, no Dependabot, no
   `SECURITY.md` disclosure policy, no SBOM.
4. Entropy/regex tiers are fail-closed, but nothing exercises ReDoS resistance of the
   pattern set against pathological inputs.

### Maintainability — 8/10

Every module is under 300 lines with a single responsibility; naming is uniform;
comments explain intent. The main risks are the duplicated CLI/config override logic
and the pattern table growing without a data-driven test harness (each new credential
pattern currently needs hand-written tests).

### Testability — 8/10

78 tests run in ~0.5 s; the streaming-equals-whole-text parametrised test and the
1 GB / 16 MB RSS memory proof are exactly the right invariants to pin. Detectors are
pure functions of text, so everything is unit-testable without fixtures.

Missing: property-based testing (the streaming equivalence invariant is a perfect
Hypothesis target), coverage measurement/gating, and Windows/macOS CI (the scheduler
and netguard touch OS-specific surfaces; only Ubuntu is exercised).

### Documentation — 7/10

The README is unusually good: honest benchmark caveats, an architecture diagram,
plugin instructions, and full CLI/API examples. `CONTRIBUTING.md`, issue templates,
and curated good-first-issues exist.

Missing: a `CHANGELOG.md`, a `SECURITY.md`, an API reference (docstrings are ready for
one), and any statement of the threat model / guarantees-and-limits of the offline
guard (it stops in-process Python socket use; it is not a container-level egress policy).

### UI/UX (CLI) — 7/10

The CLI composes well (`-` for stdin/stdout, repeatable flags, TOML policy files with
flag overrides). But a redaction run ends silently: no per-type counts, no
machine-readable report an auditor could file, no non-zero exit mode for CI secret
gates ("fail the build if anything was detected"), and no progress signal on large trees.

### API design — 8/10

`Redactor` is a small, coherent facade; `Detector` as a `runtime_checkable` Protocol is
the right extension contract; `RedactionPolicy` cleanly separates rendering. Weak
spots: `redact_file` returns `None` (callers get no counts/bytes — nothing to log or
assert on); segment-relative offsets in `detect_stream` are documented but easy to
misuse; no stats surface anywhere in the API.

### Database design — N/A (appropriateness 9/10)

There is deliberately no database, cache, or persistent state: the tool's privacy
guarantee is strongest *because* nothing is stored. Adding storage would weaken the
core value proposition. The only stateful artefact worth adding is an operator-facing
run report (counts, never content) — an output file, not a store.

### Deployment — 8/10

Multi-stage Dockerfile, wheel-based install, non-root `USER`, pinned entrypoint; PyPI
publishing via OIDC with a TestPyPI dry-run path. Missing: publishing the image itself
(GHCR), multi-arch builds, SBOM generation, image signing, and a healthcheck/labels.

### AI components — 6/10

The NER tier is a thin, lazy spaCy wrapper with sensible component exclusion for
speed. There is no confidence calibration (spaCy's fixed 0.7 is a guess), no ONNX or
transformer option for higher recall, no evaluation harness for the NER path (the
benchmarks only exercise the pattern core), and NER accuracy across chunk boundaries
is untested. The entropy tier is statistical rather than learned; that is defensible
(deterministic, explainable, no model download) but the thresholds are hand-tuned
without a documented tuning corpus.

### Novelty — 8/10

Three properties together genuinely differentiate this from Presidio/scrubadub and
from secret scanners (truffleHog, detect-secrets):

1. Constant-memory streaming with the boundary-retreat overlap algorithm — proven by
   test, not claimed.
2. A default-on offline egress guard (`netguard`) — uncommon to ship enabled by
   default, though it is best-effort in-process prevention, not a hard boundary.
3. PII **and** credentials in one pass with tiered confidence and contextual
   boost/suppress.

Each element individually has prior art (streaming scanners; `pytest-socket` uses the
same socket monkeypatch; gitleaks/detect-secrets cover credentials + entropy), so the
differentiation is the *product combination*, not a research-novel or patentable
method. What keeps it from research-grade: the accuracy evaluation was circular
(now addressed by `benchmarks/evaluate.py` against independent corpora), and the
calibration and format-awareness needed for a real contribution are not yet built.
