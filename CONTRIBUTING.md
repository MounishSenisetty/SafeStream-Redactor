# Contributing to SafeStream-Redactor

Thanks for your interest! All kinds of contributions are welcome: bug reports, docs,
new detectors, performance work, and benchmarks.

## Getting started

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pre-commit install        # run lint, format, and the strict type check on every commit
```

## Running checks

```bash
pytest                               # fast suite (~40 s), incl. property-based tests
pytest --cov=safestream_redactor     # same, with the 95% coverage gate CI enforces
ruff check . && ruff format --check .
mypy                                 # strict
pre-commit run --all-files           # everything above except the tests, in one go
pytest -m memory -o addopts=''       # constant-memory proof (slow; SAFESTREAM_MEMTEST_MB=64 to shrink)
```

CI runs all of these (plus a precision/recall quality gate and `pip-audit`) on every pull
request; they must pass before a PR can merge. The ruff version is pinned in both
`pyproject.toml` and `.pre-commit-config.yaml` so formatting is identical locally and in CI.

## Guidelines

- **Streaming first.** Nothing may buffer input proportional to file size. If your change
  touches the engine, the equivalence tests (`tests/test_properties.py`,
  `tests/test_streaming_contract.py`) and the memory test must still pass.
- **Fail closed.** This is a privacy tool: an invalid argument, config value, or overlap
  must raise a clear error, never silently fall back to something that redacts less.
- **New detectors** go in `src/safestream_redactor/detectors/`. A detector is any class with
  a `name` and a `detect(text) -> list[Detection]` method; declare its
  `StreamingRequirements` so the engine can size the overlap window. Pair every regex with
  a validator when one exists (checksums, range checks, `ipaddress`, ...), bound every
  quantifier (the kernel-hardening tests reject ReDoS-prone patterns), and add at least
  one positive and one negative test.
- **Never log or print matched text** from library code, reports, SARIF, REST `/scan`, or
  MCP tools. Only `detect --show-text` shows it, because the user explicitly asked to see it.
- **Type hints everywhere**; the package ships a `py.typed` marker and CI runs `mypy --strict`.
- **No new required dependencies.** The core must stay stdlib-only. Optional integrations
  belong in an extra (like `ner` or `onnx`).
- **Regression tests for bugs.** A fix should come with a test that fails without it.
- Keep PRs focused; one logical change per PR. Add a line under `[Unreleased]` in
  `CHANGELOG.md` for anything user-visible.

## Reporting bugs

Use the bug report issue template. For detection quality issues (false positives/negatives),
include a minimal text sample — with any *real* PII replaced by realistic fakes, please.

## Security

If you find a vulnerability, please do not open a public issue — see [SECURITY.md](SECURITY.md).
