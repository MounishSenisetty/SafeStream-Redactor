# Releasing to PyPI

How to publish `safestream-redactor` to PyPI. Publishing is automated by
[`.github/workflows/publish.yml`](../.github/workflows/publish.yml), which uses PyPI
Trusted Publishing (OIDC), so no API token is stored anywhere.

## What gets published

| File | Contents |
|---|---|
| Wheel (`safestream_redactor-X.Y.Z-py3-none-any.whl`) | The `safestream_redactor` package only |
| sdist (`safestream_redactor-X.Y.Z.tar.gz`) | `src/`, `LICENSE`, `pyproject.toml`, `PKG-INFO`, `.gitignore` (read by hatchling when pip builds from the sdist) |
| Project page text | [`src/README_PYPI.md`](../src/README_PYPI.md) |

Tests, benchmarks, docs, datasets and CI files are never published. Keep
`src/README_PYPI.md` limited to installing and using the package; the GitHub README
carries everything else.

## One-time setup

Skip any step that is already done.

1. **PyPI trusted publisher.** On https://pypi.org, open the `safestream-redactor`
   project → *Settings* → *Publishing* → *Add a new publisher* → *GitHub*:
   owner `MounishSenisetty`, repository `SafeStream-Redactor`, workflow `publish.yml`,
   environment `pypi`.
2. **TestPyPI trusted publisher.** The same on https://test.pypi.org (a separate
   account), with environment `testpypi`.
3. **GitHub environments.** Repository → *Settings* → *Environments* → create `pypi` and
   `testpypi`. Adding yourself as a *required reviewer* on `pypi` makes every upload wait
   for a click.

## Each release

Throughout, `X.Y.Z` is the new version. A version can be uploaded to PyPI only once, ever,
even after deletion, so pick it carefully. Published so far: 0.1.0, 0.2.0, 0.3.0.

1. **Start from a green `main`.** Merge the work being released and wait for CI.
2. **Bump the version** in `src/safestream_redactor/__init__.py`:
   ```python
   __version__ = "X.Y.Z"
   ```
   It is the only place the package version is defined (`pyproject.toml` reads it).
3. **Update `CHANGELOG.md`**: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and
   add a new empty `## [Unreleased]` above it.
4. **Check the build locally** from a clean checkout:
   ```bash
   rm -rf dist
   python -m pip install --upgrade build twine
   python -m build
   twine check --strict dist/*
   tar tzf dist/*.tar.gz                    # only src/, LICENSE, metadata
   python -m venv /tmp/rel && /tmp/rel/bin/pip install dist/*.whl
   /tmp/rel/bin/safestream --version        # safestream X.Y.Z
   printf 'mail bob@corp.io\n' | /tmp/rel/bin/safestream redact - -o -
   ```
5. **Commit and merge** the version bump (`release: vX.Y.Z`) through a pull request.
6. **Dry run on TestPyPI** (recommended): *Actions* → *Publish* → *Run workflow* on `main`
   (target `testpypi`), then install it from there:
   ```bash
   pip install -i https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ "safestream-redactor==X.Y.Z"
   ```
   TestPyPI also accepts each version only once. Retrying needs a new version, or a
   pre-release such as `X.Y.Zrc1` used only for the dry run.
7. **Create the GitHub release.** The tag must be `v` + the version:
   ```bash
   git switch main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
   Then *Releases* → *Draft a new release* → choose tag `vX.Y.Z`, paste the CHANGELOG
   section as the notes, and *Publish release*.
8. **Let the workflow publish.** The published release triggers `publish.yml`:
   - builds the wheel and sdist;
   - stops if the tag does not match `__version__`;
   - runs `twine check --strict`;
   - installs the wheel and the sdist into clean environments and runs a redaction;
   - uploads to PyPI (after approval, if the `pypi` environment requires it).

   The same release also triggers `docker.yml`, which publishes the container image.
9. **Verify:**
   ```bash
   pip install --no-cache-dir --upgrade "safestream-redactor==X.Y.Z"
   safestream --version
   ```
   and check the project page at https://pypi.org/project/safestream-redactor/.

## When something goes wrong

- **The workflow fails before the upload step** (version mismatch, `twine check`, smoke
  test): nothing reached PyPI. Delete the GitHub release and the tag
  (`git push origin :refs/tags/vX.Y.Z`), fix the problem, and repeat from step 5.
- **A broken version is already on PyPI**: it cannot be replaced. On PyPI, open the
  release → *Options* → *Yank*, which stops new installs from picking it, then release
  `X.Y.Z+1` with the fix.
- **Manual upload** (only if Trusted Publishing is unavailable): create an API token
  scoped to this project on PyPI, then:
  ```bash
  python -m build && twine check --strict dist/*
  TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-... twine upload dist/*
  ```

## The optional native wheel

`safestream-redactor-native` is a separate PyPI project, built by
[`.github/workflows/native-wheels.yml`](../.github/workflows/native-wheels.yml). It has
never been published, so `pip install 'safestream-redactor[native]'` fails until it is.
To publish it:

1. Add a trusted publisher for the `safestream-redactor-native` project with workflow
   `native-wheels.yml` and environment `pypi-native` (the first upload creates the
   project; use PyPI's *pending publisher* form for that).
2. Set `version` in `native/Cargo.toml` to the same `X.Y.Z` as the main package.
3. Push a tag `native-vX.Y.Z`. The workflow builds wheels for Linux, macOS and Windows,
   runs the byte-identity tests against them, and publishes.
