## Summary

<!-- What does this change and why? Link the issue it closes, if any. -->

## Type of change

- [ ] Bug fix (detection, redaction, or streaming correctness)
- [ ] New detector / entity type
- [ ] Performance
- [ ] Docs, tooling, or CI

## Checklist

- [ ] `pytest` passes and new behaviour has a test (a regression test for bug fixes)
- [ ] `ruff check .`, `ruff format --check .`, and `mypy` are clean (or `pre-commit run --all-files`)
- [ ] Streaming still holds: nothing buffers input in proportion to file size
- [ ] New detectors declare `StreamingRequirements` and pair each regex with a validator where one exists
- [ ] No real secrets or PII in tests, fixtures, or this description — use realistic fakes
- [ ] `CHANGELOG.md` updated under `[Unreleased]` for user-visible changes
