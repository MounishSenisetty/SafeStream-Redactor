# Publishing a pre-exported ONNX NER model

`safestream fetch-model` makes the [ONNX NER tier](DETECTORS.md#the-optional-onnx-ner-tier)
turnkey: a user runs one command and the tier auto-enables. The package ships **no**
model (the base install stays pure-Python, offline and dependency-free), so a
maintainer publishes a model artifact once and pins its checksum. This page is that
one-time workflow.

The artifact is a `.tar.gz` holding, at the top level, the three files the tier
discovers: `model.int8.onnx`, `tokenizer.json` (or `vocab.json`), and `labels.json`.
The fetcher installs only those flat basenames and verifies the whole archive
against a SHA-256, so the host only needs to serve a static file.

## Easiest: the one-click workflow

**Actions → Publish model → Run workflow.** The
[`publish-model.yml`](../.github/workflows/publish-model.yml) workflow runs the whole
pipeline on a GitHub runner — where `torch` and Hugging Face are reachable — so no
local toolchain is needed. It exports the checkpoint (default `dslim/distilbert-NER`),
packages the `.tar.gz`, creates/updates the release (default tag `models-v1`) with the
asset, and opens a PR that pins the artifact's SHA-256 in the registry. Merge that PR
and `safestream fetch-model` is turnkey.

It uses only the built-in `GITHUB_TOKEN`. Opening the pin PR needs the repo setting
**Settings → Actions → General → "Allow GitHub Actions to create and approve pull
requests"**; without it the asset is still published and the digest is printed in the
run summary to pin by hand (step 3 below). The manual steps below are the same pipeline
if you would rather run it yourself.

## 1. Export the model

On a machine with the export toolchain (`pip install 'safestream-redactor[onnx]'`
plus `torch`, `transformers`, `onnx`), export and package:

```bash
python scripts/export_onnx.py --out ./dist/ner \
    --archive distilbert-conll03-int8.tar.gz   # exports, packages, and prints MODEL_SHA256=<digest>
```

`--archive` writes exactly the three files the fetcher installs and prints the digest
to pin (`MODEL_SHA256=…`); it is the same packaging the fetcher verifies against.

Pick a checkpoint whose licence permits redistribution and record it in the release
notes. The default `dslim/distilbert-NER` builds on DistilBERT (Apache-2.0); confirm
the fine-tune's own terms before publishing weights.

## 2. Publish the artifact

Upload the `.tar.gz` as a **GitHub release asset** (any static HTTPS host works). The
default registry entry expects a release tagged `models-v1`:

```
https://github.com/<owner>/SafeStream-Redactor/releases/download/models-v1/distilbert-conll03-int8.tar.gz
```

Using `gh`:

```bash
gh release create models-v1 distilbert-conll03-int8.tar.gz \
    --title "ONNX NER model v1" --notes "DistilBERT CoNLL-03 INT8. SHA-256: <digest>"
```

## 3. Pin the checksum

Set the recorded digest on the registry entry in
[`src/safestream_redactor/models.py`](../src/safestream_redactor/models.py) so an
unparameterised `safestream fetch-model` verifies the download:

```python
DEFAULT_MODEL = ModelSpec(
    name="distilbert-conll03-int8",
    url="https://github.com/.../releases/download/models-v1/distilbert-conll03-int8.tar.gz",
    sha256="<the sha256sum from step 1>",
    ...
)
```

Until a digest is pinned, `fetch-model` **refuses** an unparameterised run rather than
install an unverified ONNX graph (which `onnxruntime` would run in-process). Users can
still fetch a model they trust with explicit `--url`/`--sha256`, or `--allow-unverified`.

## Why fetch, not bundle

A useful NER model is tens of megabytes — too large for the wheel, and bundling it
would force `onnxruntime` into every install and drop the default throughput by orders
of magnitude. Keeping the model a separate, verified, opt-in download preserves the
zero-dependency, constant-memory, offline default while making the accuracy tier one
command away for anyone who wants it. The download is the only networked command in the
package; redaction, detection and the servers never reach the network.
