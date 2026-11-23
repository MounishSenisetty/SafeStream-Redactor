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

## 1. Export the model

On a machine with the export toolchain (`pip install 'safestream-redactor[onnx]'`
plus `torch`, `transformers`, `onnx`), export and package:

```bash
python scripts/export_onnx.py --out ./dist/ner      # model.int8.onnx + tokenizer.json + labels.json
tar -C ./dist/ner -czf distilbert-conll03-int8.tar.gz \
    model.int8.onnx tokenizer.json labels.json
sha256sum distilbert-conll03-int8.tar.gz            # record this digest
```

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
