# Releasing to PyPI

One GitHub release publishes one distribution to PyPI, `safestream-redactor`: a
`py3-none-any` wheel and an sdist, pure Python with no third-party runtime
dependencies.

The optional Rust core in `native/` is **not** published. `native-wheels.yml` still
builds and tests its wheels on every platform, and users build it from source with
`pip install 'git+https://github.com/MounishSenisetty/SafeStream-Redactor#subdirectory=native'`
(needs a Rust toolchain). Its version is kept equal to the package's.

Publishing is automated by [`.github/workflows/publish.yml`](../.github/workflows/publish.yml)
with PyPI Trusted Publishing (OIDC), so no API token is stored anywhere.

## What the pipeline checks before anything is uploaded

`publish.yml` runs [`package.yml`](../.github/workflows/package.yml), which:
- builds the package and runs `twine check --strict`;
- checks that unfinished code (`memstream/`) is in neither artifact;
- installs the **wheel** into clean interpreters on Linux, macOS and Windows, on
  Python 3.10 and 3.14, with the `[crypto]` and `[ui]` extras;
- installs the **sdist**, runs `pipx run safestream-redactor`, and installs into
  Alpine (musl).

Every install runs [`scripts/smoke_test.py`](../scripts/smoke_test.py), which you can
also run by hand in any virtualenv: `python scripts/smoke_test.py --crypto --ui`.

## One-time setup

Skip any step that is already done.

1. **Trusted publishers.** On the `safestream-redactor` project on https://pypi.org
   (and on https://test.pypi.org for dry runs), *Manage* → *Publishing*, add a GitHub
   publisher with owner `MounishSenisetty`, repository `SafeStream-Redactor`, workflow
   `publish.yml` and environment `pypi` (on TestPyPI: `testpypi`).
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
   `native/Cargo.lock`.
   `tests/test_packaging.py` fails if any of them is edited by hand and drifts.
3. **Update `CHANGELOG.md`**: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, and
   add a new empty `## [Unreleased]` above it.
4. **Check the build locally** (optional; CI repeats all of it):
   ```bash
   rm -rf dist && python -m build && twine check --strict dist/*
   python -m venv /tmp/rel
   /tmp/rel/bin/pip install --no-index --find-links dist "safestream-redactor==X.Y.Z"
   /tmp/rel/bin/python scripts/smoke_test.py
   ```
5. **Commit and merge** the change (`release: vX.Y.Z`) through a pull request.
6. **Dry run on TestPyPI** (recommended): *Actions* → *Publish* → *Run workflow* on
   `main`, target `testpypi`. The run stamps a unique `X.Y.(Z+1).devN` version, so it
   can be repeated freely. It uploads the package, then installs it back from
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
   pip install --no-cache-dir "safestream-redactor==X.Y.Z"
   python scripts/smoke_test.py
   ```
   and check the project page on PyPI.

## When something goes wrong

- **The workflow fails before an upload step:** nothing reached PyPI. Delete the
  GitHub release and the tag (`git push origin :refs/tags/vX.Y.Z`), fix the problem,
  and repeat from step 5.
- **A broken version is already on PyPI:** it cannot be replaced. On PyPI, open the
  release → *Options* → *Yank*, then release
  `X.Y.Z+1` with the fix.
- **Manual upload** (only if Trusted Publishing is unavailable): create an API token
  scoped to the project on PyPI, then:
  ```bash
  TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-... twine upload dist/*
  ```
