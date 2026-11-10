# Releasing to PyPI

One GitHub release publishes **both** distributions, at the same version:

| Distribution | What it is | Files |
|---|---|---|
| `safestream-redactor` | The package: pure Python, no third-party runtime dependencies | one `py3-none-any` wheel + sdist |
| `safestream-redactor-native` | The optional Rust core behind `pip install 'safestream-redactor[native]'` | one abi3 wheel per platform + sdist |

Native wheels are built for Linux x86_64/aarch64 (manylinux and musllinux), macOS
Intel/Apple Silicon and Windows x64. On any other platform pip builds the native sdist,
which needs a Rust toolchain. The base package installs everywhere either way.

Publishing is automated by [`.github/workflows/publish.yml`](../.github/workflows/publish.yml)
with PyPI Trusted Publishing (OIDC), so no API token is stored anywhere.

## What the pipeline checks before anything is uploaded

`publish.yml` runs two reusable workflows, then a gate across them:

1. [`package.yml`](../.github/workflows/package.yml), for the pure-Python package:
   - builds it and runs `twine check --strict`;
   - checks that unfinished code (`memstream/`) is in neither artifact;
   - installs the **wheel** into clean interpreters on Linux, macOS and Windows, on
     Python 3.10 and 3.14, with the `[crypto]` and `[ui]` extras;
   - installs the **sdist**, runs `pipx run safestream-redactor`, and installs into
     Alpine (musl).
2. [`native-wheels.yml`](../.github/workflows/native-wheels.yml), for the Rust core:
   - builds every wheel and the sdist;
   - installs **each wheel on its own platform** and requires the native core to be
     active, with no fallback warning;
   - runs the byte-identity tests on every supported CPython;
   - runs Rust fmt, clippy and tests;
   - compiles the sdist from source.
3. `hybrid-install`: on four platforms, runs the exact
   `pip install 'safestream-redactor[native]==X.Y.Z'` a user would, resolved only
   against the artifacts about to be uploaded.

Every install runs [`scripts/smoke_test.py`](../scripts/smoke_test.py), which you can
also run by hand in any virtualenv: `python scripts/smoke_test.py --native --crypto --ui`.

The upload sends the native files first, because the main package's `[native]` extra
pins them exactly.

## One-time setup

Skip any step that is already done.

1. **Trusted publishers, four in total.** For each project (`safestream-redactor` and
   `safestream-redactor-native`) on each index (https://pypi.org and
   https://test.pypi.org), add a GitHub publisher with:
   - owner `MounishSenisetty`, repository `SafeStream-Redactor`;
   - workflow `publish.yml`;
   - environment `pypi` (on TestPyPI: `testpypi`).

   `safestream-redactor-native` does not exist yet. Use the **pending publisher** form
   (*Your account* → *Publishing*). The first upload creates the project. If
   `safestream-redactor` already has a publisher for `publish.yml`, nothing changes for
   it.
2. **GitHub environments.** Repository → *Settings* → *Environments* → `pypi` and
   `testpypi`. Adding yourself as a *required reviewer* on `pypi` makes every upload
   wait for a click.

## Each release

`X.Y.Z` is the new version. PyPI accepts a version only once, ever, even after
deletion. The published versions are listed at https://pypi.org/project/safestream-redactor/#history.

1. **Start from a green `main`.** Merge the work being released and wait for CI.
2. **Set the version, everywhere at once:**
   ```bash
   python scripts/set_version.py X.Y.Z
   ```
   This writes `src/safestream_redactor/__init__.py`, `native/Cargo.toml` and
   `native/Cargo.lock`, and the `[native]` pin in `pyproject.toml`.
   `tests/test_packaging.py` fails if any of them is edited by hand and drifts.
3. **Update `CHANGELOG.md`**: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, and
   add a new empty `## [Unreleased]` above it.
4. **Check the build locally** (optional; CI repeats all of it):
   ```bash
   rm -rf dist && python -m build && twine check --strict dist/*
   (cd native && maturin build --release --out ../dist)
   python -m venv /tmp/rel
   /tmp/rel/bin/pip install --no-index --find-links dist "safestream-redactor[native]==X.Y.Z"
   /tmp/rel/bin/python scripts/smoke_test.py --native
   ```
5. **Commit and merge** the change (`release: vX.Y.Z`) through a pull request.
6. **Dry run on TestPyPI** (recommended): *Actions* → *Publish* → *Run workflow* on
   `main`, target `testpypi`. The run stamps a unique `X.Y.(Z+1).devN` version, so it
   can be repeated freely. It uploads both projects, then installs them back from
   TestPyPI on Linux, macOS and Windows. The version is shown in the run summary.
   Target `check` runs every build and test without uploading anything.
7. **Create the GitHub release.** The tag must be `v` + the version:
   ```bash
   git switch main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
   Then *Releases* → *Draft a new release* → choose tag `vX.Y.Z`, paste the CHANGELOG
   section as the notes, and *Publish release*. The workflow stops before building if
   the tag does not match the version.
8. **Let the workflow publish.** After the checks above, it uploads to PyPI (after
   approval, if `pypi` requires a reviewer). The same release triggers `docker.yml`,
   which publishes the container image.
9. **Verify:**
   ```bash
   pip install --no-cache-dir "safestream-redactor[native]==X.Y.Z"
   python scripts/smoke_test.py --native
   ```
   and check both project pages on PyPI.

## When something goes wrong

- **The workflow fails before an upload step:** nothing reached PyPI. Delete the
  GitHub release and the tag (`git push origin :refs/tags/vX.Y.Z`), fix the problem,
  and repeat from step 5.
- **The native upload succeeded but the main upload failed:** re-run the failed job.
  The native step skips files that are already on PyPI, so the re-run goes straight to
  the main upload.
- **A broken version is already on PyPI:** it cannot be replaced. On PyPI, open the
  release → *Options* → *Yank* (for both projects, if both are affected), then release
  `X.Y.Z+1` with the fix.
- **Manual upload** (only if Trusted Publishing is unavailable): create an API token
  scoped to the project on PyPI, then:
  ```bash
  TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-... twine upload dist/*
  ```
