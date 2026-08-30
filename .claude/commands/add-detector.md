---
description: Scaffold and implement a new detector following the full workflow.
argument-hint: <entity-type-name> [format description]
---

Add a new detector to SafeStream-Redactor for: **$ARGUMENTS**

Follow the `add-a-detector` skill end to end. Concretely:

1. Add the `EntityType` member and classify its severity.
2. Implement the detector — prefer an anchored, span-bounded `Pattern` with a
   validator in `src/safestream_redactor/detectors/deterministic.py`.
3. Add positive fixtures, hard-negative fixtures (UUIDs, hashes, version
   strings, base64 — whatever this format is confusable with), and a
   boundary-split case in `tests/test_boundary_adversarial.py`.
4. Run and report: `python -m pytest -q`, `ruff check src tests`,
   `ruff format --check src tests`, `mypy`.
5. Update `docs/DETECTORS.md` and `CHANGELOG.md`.

Do not claim completion until every gate is green. Never print or commit real
secrets — use clearly fake example values in fixtures.
