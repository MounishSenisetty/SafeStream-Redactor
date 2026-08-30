---
name: add-a-detector
description: >-
  End-to-end workflow for adding a new PII/credential detector to
  SafeStream-Redactor. Use when someone wants to detect a new secret format or
  entity type, extend the deterministic tier, or ship a third-party detector
  plugin. Covers design, streaming-boundary safety, fixtures, false-positive
  hardening, benchmarking, registration, and CI validation.
---

# Adding a detector to SafeStream-Redactor

A detector is anything satisfying the `Detector` protocol
(`src/safestream_redactor/detectors/base.py`): a `name` and a
`detect(text) -> list[Detection]`. Most new detectors are one more `Pattern` in
the deterministic tier; some are standalone classes. Follow every step — a
detector that skips the boundary or false-positive work is a precision/recall
regression waiting to happen.

## 0. Decide the tier

- **Named format with a validator** (a token prefix, a checksum, a fixed
  shape) → add a `Pattern` to `src/safestream_redactor/detectors/deterministic.py`.
  This is the common case and the highest-precision one.
- **Statistical** (no published format, high entropy) → the entropy tier
  already covers this; tune it rather than adding a new one.
- **Model-based / third-party** → a standalone class, optionally shipped as a
  plugin via the `safestream_redactor.detectors` entry-point group.

## 1. Add the entity type

In `src/safestream_redactor/entities.py`, add a member to `EntityType`. Choose a
lowercase, underscore-free-where-possible value; it becomes the CLI `--types`
name and the SARIF/MCP `ruleId`. Then classify its severity in
`src/safestream_redactor/severity.py` — credentials are `CRITICAL`/`HIGH`, PII
is usually `MEDIUM`, weakly identifying data is `LOW`.

## 2. Write the pattern (deterministic tier)

Add a `Pattern(...)` to `_PATTERNS`. Requirements:

- **Anchor it.** Set `anchors=(...)` / `anchors_lower=(...)` /
  `needs_digit=True` to a literal every match must contain. The prefilter skips
  the regex when no anchor is present — this is what keeps the scanner fast on
  secret-sparse text. A differential test (`tests/test_prefilter.py`) enforces
  that the prefilter never changes output, so a wrong anchor fails CI.
- **Bound the span.** The regex must not be able to match longer than the
  streaming overlap (default 8192). Use bounded quantifiers (`{1,8100}`), never
  an unbounded `+`/`*` across the whole value. An unbounded span breaks the
  boundary guarantee AND opens a ReDoS hole. If your detector can legitimately
  emit long spans, declare it (step 4).
- **Add a validator** when a syntactic match is not proof (Luhn for cards,
  `ipaddress` for IPs, a checksum for the token). Return `False` to reject.
- **Score it.** Confidence ≥ 0.5 shows by default; below that it survives only
  when the contextual tier finds a trigger word nearby. Precise, anchored
  credential formats score 0.9+.

## 3. Declare streaming requirements

If your detector is a standalone class (not a `Pattern`), give it a
`requirements = StreamingRequirements(max_span=..., left_context=...,
right_context=...)` attribute (see `base.py`). The engine derives its overlap
from the maximum across active detectors (`engine.required_overlap`), so an
honest `max_span` is what keeps a boundary-split entity detectable. Omitting it
falls back to the conservative default (8192).

## 4. Fixtures — positives, negatives, and boundaries

Add to `tests/test_detectors.py` (or a new module):

1. **Positives**: real-shaped examples (use clearly fake values) that must be
   detected, asserting the entity type and span.
2. **Hard negatives**: the look-alikes that must NOT fire — UUIDs, git hashes,
   version strings, order IDs, base64 blobs, timestamps. This is where
   precision is won or lost.
3. **Boundary splits**: add a case to `tests/test_boundary_adversarial.py` that
   feeds the secret split at every byte position across several chunk sizes and
   asserts identical redacted output. Any secret up to the overlap must survive
   being cut by a chunk boundary.

## 5. Run the gates locally

```bash
python -m pytest -q                       # all tests, including your fixtures
ruff check src tests && ruff format --check src tests
mypy                                      # strict typing
python -m pytest -m memory -o addopts=''  # constant-memory tests (optional, slow)
```

The detection-quality benchmark (`benchmarks/evaluate.py`) enforces
precision/recall floors on labeled corpora; if your detector is broad, run it to
confirm you did not lower precision for existing types:

```bash
python benchmarks/evaluate.py
```

## 6. Register a plugin (third-party detectors only)

Expose the class under the `safestream_redactor.detectors` entry-point group in
your package's `pyproject.toml`:

```toml
[project.entry-points."safestream_redactor.detectors"]
my_detector = "my_pkg.module:MyDetector"
```

`Redactor(load_plugins=True)` (the default) discovers it. Plugin load failures
are logged, never silent — a vanished tier is a coverage loss, so watch the
warning.

## 7. Document

Note the new type in `docs/DETECTORS.md` and `CHANGELOG.md`. If it is a
credential, add it to the coverage list in the README.

## Checklist

- [ ] `EntityType` member + severity classification
- [ ] Anchored, span-bounded pattern (+ validator if needed)
- [ ] `StreamingRequirements` if standalone
- [ ] Positive fixtures
- [ ] Hard-negative fixtures
- [ ] Boundary-split test
- [ ] `pytest`, `ruff`, `mypy` green
- [ ] Benchmark precision/recall not regressed
- [ ] Docs + changelog updated
