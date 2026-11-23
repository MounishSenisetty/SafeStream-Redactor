"""Fetch a pre-exported ONNX NER model into the tier's auto-discovery directory.

The redactor ships no model (the base install stays pure-Python and offline). This
module is the *opt-in* acquisition step that makes the ONNX NER tier turnkey: it
downloads a model published as a release artifact, verifies it against a pinned
SHA-256, and unpacks it into
:func:`~safestream_redactor.detectors.onnx_ner.default_model_dir`, after which the
tier auto-enables with no flags (see :mod:`detectors.onnx_ner`).

This is the one place in the package that reaches the network, and only when a
person runs ``safestream fetch-model`` (or calls :func:`fetch_model`). The
redaction, detection and server paths never fetch anything and keep running under
the in-process offline guard; downloading a model is a separate, explicit action.

Verification is fail-closed: a download whose SHA-256 does not match the expected
digest is discarded and never installed, and with no expected digest the fetch
refuses unless the caller passes ``--allow-unverified`` (``allow_unverified=True``),
because an unverified ONNX graph is run by ``onnxruntime`` in-process.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen

from safestream_redactor.detectors.onnx_ner import (
    _MODEL_NAMES,
    _VOCAB_NAMES,
    default_model_dir,
)

#: Hard cap on a model download, so a wrong URL cannot exhaust the disk.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024

#: Files a model archive may install, by basename. Anything else is ignored, and
#: unsafe member names (absolute, or containing a path separator) are refused.
_ALLOWED_MEMBERS = frozenset({*_MODEL_NAMES, *_VOCAB_NAMES, "labels.json"})

#: Override the download URL / digest without editing code (used by the CLI too).
ENV_MODEL_URL = "SAFESTREAM_MODEL_URL"
ENV_MODEL_SHA256 = "SAFESTREAM_MODEL_SHA256"


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """A publishable model artifact: where to get it and how to verify it."""

    name: str
    url: str
    #: Lowercase hex SHA-256 of the ``.tar.gz`` artifact, or ``None`` when no
    #: official artifact has been published and pinned for this release yet.
    sha256: str | None
    description: str = ""
    license: str = ""


# The default model the ONNX NER tier targets. The artifact is a .tar.gz holding
# model.int8.onnx + tokenizer.json + labels.json (the layout scripts/export_onnx.py
# writes). Published as a GitHub release asset on the project repo; until a
# maintainer uploads one and pins its digest here, sha256 is None and an
# unparameterised fetch refuses rather than install something unverified.
DEFAULT_MODEL = ModelSpec(
    name="distilbert-conll03-int8",
    url=(
        "https://github.com/MounishSenisetty/SafeStream-Redactor/releases/download/"
        "models-v1/distilbert-conll03-int8.tar.gz"
    ),
    sha256=None,
    description="DistilBERT fine-tuned on CoNLL-03 (PER/ORG/LOC), INT8 ONNX.",
    license="Apache-2.0 (base model); see the release notes for the fine-tune's terms.",
)

REGISTRY: dict[str, ModelSpec] = {DEFAULT_MODEL.name: DEFAULT_MODEL}


class ModelVerificationError(Exception):
    """A downloaded artifact did not match its expected SHA-256."""


def _safe_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """The regular-file members we recognise, rejecting path-traversal names."""
    out: list[tarfile.TarInfo] = []
    for member in tar.getmembers():
        if not member.isfile():
            continue
        name = member.name
        base = os.path.basename(name)
        # reject absolute paths, parent escapes, and any nested layout: we only
        # ever install flat, allow-listed basenames into the destination dir.
        if base != name.lstrip("./") or base in ("", ".", "..") or base not in _ALLOWED_MEMBERS:
            continue
        out.append(member)
    return out


def _download(url: str, dest: Path, progress: Callable[[int, int], None] | None) -> None:
    """Stream ``url`` to ``dest``, honouring :data:`MAX_DOWNLOAD_BYTES`."""
    # urlopen honours HTTP(S)_PROXY from the environment, so it works behind a proxy.
    with urlopen(url) as resp:
        total = int(resp.headers.get("Content-Length", 0) or 0)
        read = 0
        with dest.open("wb") as fh:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                read += len(chunk)
                if read > MAX_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"model download exceeds {MAX_DOWNLOAD_BYTES} bytes; refusing "
                        f"(wrong URL?): {url}"
                    )
                fh.write(chunk)
                if progress is not None:
                    progress(read, total)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_model(
    model: str | ModelSpec = DEFAULT_MODEL,
    *,
    dest: str | os.PathLike[str] | None = None,
    url: str | None = None,
    sha256: str | None = None,
    allow_unverified: bool = False,
    force: bool = False,
    progress: Callable[[int, int], None] | None = None,
) -> Path:
    """Download, verify and install an ONNX NER model; return the install directory.

    ``model`` is a registry name or a :class:`ModelSpec`. ``url`` / ``sha256``
    override the spec (and the ``SAFESTREAM_MODEL_URL`` / ``_SHA256`` env vars
    override the defaults). ``dest`` defaults to
    :func:`~safestream_redactor.detectors.onnx_ner.default_model_dir`.

    Raises :class:`ModelVerificationError` on a digest mismatch, and
    :class:`ValueError` when no digest is available and ``allow_unverified`` is
    False. Nothing is written to ``dest`` unless verification passes.
    """
    spec = REGISTRY[model] if isinstance(model, str) else model
    url = url or os.environ.get(ENV_MODEL_URL) or spec.url
    expected = (sha256 or os.environ.get(ENV_MODEL_SHA256) or spec.sha256 or "").strip().lower()
    if not expected and not allow_unverified:
        raise ValueError(
            "no SHA-256 is pinned for this model, so it cannot be verified. Pass a "
            "digest (--sha256 / sha256=), or --allow-unverified to install without a "
            "checksum (an unverified ONNX graph is run in-process). A maintainer pins "
            "the official digest in safestream_redactor/models.py once published."
        )
    target = Path(dest).expanduser() if dest is not None else default_model_dir()
    existing_model = any((target / name).is_file() for name in _MODEL_NAMES)
    if existing_model and not force:
        raise FileExistsError(
            f"a model is already installed in {target}; pass --force to replace it"
        )

    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "model.tar.gz"
        _download(url, archive, progress)
        if expected:
            actual = _sha256(archive)
            if actual != expected:
                raise ModelVerificationError(
                    f"SHA-256 mismatch for {url}: expected {expected}, got {actual}. "
                    "The artifact was not installed."
                )
        staging = Path(tmp) / "unpacked"
        staging.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            members = _safe_members(tar)
            names = {os.path.basename(m.name) for m in members}
            if not (names & set(_MODEL_NAMES)) or not (names & set(_VOCAB_NAMES)):
                raise ValueError(
                    f"archive {url} is missing a model and/or vocab file "
                    f"(found {sorted(names)}); expected one of {sorted(_MODEL_NAMES)} "
                    f"and one of {sorted(_VOCAB_NAMES)}"
                )
            for member in members:
                src = tar.extractfile(member)
                if src is None:  # pragma: no cover - isfile() filtered above
                    continue
                with (staging / os.path.basename(member.name)).open("wb") as out:
                    shutil.copyfileobj(src, out)
        # Move verified files into place only after the whole archive is sound.
        for file in staging.iterdir():
            shutil.move(str(file), str(target / file.name))
    return target
