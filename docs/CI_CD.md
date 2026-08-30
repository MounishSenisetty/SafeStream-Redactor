# CI/CD Secret Gate

SafeStream's detector is a competitive secret scanner; one flag turns it into a
gate that blocks secrets before they land.

```bash
safestream detect .                       # list findings
safestream detect . --fail-on-detect      # exit 1 if anything is found
safestream detect file1 file2 --fail-on-detect   # scan many files (staged-file gate)
safestream detect . --sarif > results.sarif      # SARIF 2.1.0 for code scanning
```

Exit codes: `0` clean, `1` findings present (with `--fail-on-detect`), `3`
memory-budget refusal. Findings printed to the gate are content-free in SARIF
mode; the human/JSON modes show the match for local triage.

## Pre-commit

`.pre-commit-hooks.yaml` defines the `safestream-detect` hook. In a consuming
repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/MounishSenisetty/SafeStream-Redactor
    rev: v0.4.0
    hooks:
      - id: safestream-detect
```

The hook receives the staged files as arguments and fails the commit when any
contains a detectable secret. It runs offline and never prints the secret.

## GitHub Action

`action.yml` is a composite action:

```yaml
- uses: MounishSenisetty/SafeStream-Redactor@v0.4.0
  with:
    paths: "."
    sarif-file: results.sarif        # optional
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

The action installs the package from PyPI, scans `paths`, fails the job on any
finding, and optionally writes a SARIF report you upload to GitHub code scanning.

## SARIF

`detect --sarif` emits SARIF 2.1.0. Severity maps to SARIF level
(critical/high → `error`, medium → `warning`, low → `note`) and to a
`security-severity` score GitHub uses to sort alerts. The report carries the
entity type, character offsets, confidence, and severity of each finding — **never
the matched value** (`tests/test_sarif.py::test_sarif_never_contains_secret_text`).
Each finding carries its own file URI, so one report spans a whole scan.
