# CI/CD Secret Gate

SafeStream's detector is a competitive secret scanner; one flag turns it into a
gate that blocks secrets before they land.

```bash
safestream detect .                                # list findings (file:line:col)
safestream detect . --hide-text --fail-on-detect   # CI gate: exit 1 on any finding
safestream detect file1 file2 --fail-on-detect     # scan many files (staged-file gate)
safestream detect . --sarif > results.sarif        # SARIF 2.1.0 for code scanning
```

Exit codes: `0` clean, `1` findings present (with `--fail-on-detect`) or a runtime
error, `3` memory-budget refusal.

**Keep secrets out of build logs.** Human and JSON output show the matched text
for local triage. Anything a CI system captures should use `--hide-text`, which
prints only the type, `file:line:col`, and confidence (the JSON records drop their
`text` field). The bundled pre-commit hook and GitHub Action always pass it. SARIF
output never contains matched text.

**Directories** are walked recursively in sorted order. Symlinks are skipped (a
link cannot pull an out-of-tree file into the scan), as are `.git/`, `.hg/`,
`.svn/`, and binary files (a NUL byte in the first 8 KiB). A file named explicitly
on the command line is always scanned.

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
contains a detectable secret. It runs offline and, via `--hide-text`, never
prints the secret — only `file:line:col`, type, and confidence.

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

The action installs the package from PyPI, scans `paths` (space-separated files
or directories), fails the job on any finding without echoing the secret into the
log, and optionally writes a SARIF report you upload to GitHub code scanning.
Inputs reach its scripts only through environment variables, never by `${{ }}`
interpolation into the script text. `tests/test_ci_integrations.py` runs the
action's scan step end to end.

## SARIF

`detect --sarif` emits SARIF 2.1.0. Severity maps to SARIF level
(critical/high → `error`, medium → `warning`, low → `note`) and to a
`security-severity` score GitHub uses to sort alerts. The report carries the
entity type, location (`startLine`/`startColumn`/`endLine`/`endColumn`, which
GitHub code scanning needs to place an alert, plus character offsets; columns
count Unicode code points, declared via `columnKind`), confidence, and severity of
each finding — **never the matched value** (`tests/test_sarif.py::test_sarif_never_contains_secret_text`).
Each finding carries its own file URI, so one report spans a whole scan.
