# Contributing to SafeStream-Redactor

Thanks for your interest! All kinds of contributions are welcome: bug reports, docs,
new detectors, performance work, and benchmarks.

## Getting started

```bash
git clone https://github.com/MounishSenisetty/SafeStream-Redactor
cd SafeStream-Redactor
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

## Running checks

```bash
pytest                       # fast test suite
ruff check .                 # lint
ruff format .                # format
pytest -m memory -o addopts=''   # constant-memory test (slow; SAFESTREAM_MEMTEST_MB=64 to shrink)
```

All three must pass in CI before a PR can merge.

## Guidelines

- **Streaming first.** Nothing may buffer input proportional to file size. If your change
  touches the engine, the equivalence test (`test_streaming_equals_whole_text`) and the
  memory test must still pass.
- **New detectors** go in `src/safestream_redactor/detectors/`. A detector is any class with
  a `name` and a `detect(text) -> list[Detection]` method. Pair every regex with a validator
  when one exists (checksums, range checks, `ipaddress`, ...), and add at least one positive
  and one negative test.
- **Type hints everywhere**; the package ships a `py.typed` marker.
- **No new required dependencies.** The core must stay stdlib-only. Optional integrations
  belong in an extra (like `ner`).
- Keep PRs focused; one logical change per PR.

## Reporting bugs

Use the bug report issue template. For detection quality issues (false positives/negatives),
include a minimal text sample — with any *real* PII replaced by realistic fakes, please.

## Security

If you find a vulnerability, please do not open a public issue — email the maintainer instead.
