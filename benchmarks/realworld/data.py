"""Layout, validation and loading of an authorised real-world evaluation corpus.

The corpus never enters the repository. It lives in ``SAFESTREAM_REALWORLD_DIR``
(default ``benchmarks/data/external/realworld/``, which is git-ignored)::

    provenance.json            who authorised the data, under which agreement
    documents.jsonl            {"doc_id", "text", "source", "kind"} per line
    annotations/<name>.jsonl   one file per annotator (at least two)
    adjudicated.jsonl          the gold standard after adjudication

An annotation line is ``{"doc_id": ..., "spans": [{"start", "end", "type",
"subtype"?, "necessity"?}]}``. Every document must appear in every annotation file,
with an empty ``spans`` list when the annotator found nothing: a missing line and
"nothing sensitive here" are different judgements. ``necessity`` defaults to
``mandatory`` because every annotated value in a real artefact must be redacted;
``contextual`` marks values the annotators agree may stay.

Nothing in this module writes document text anywhere. Reports carry counts, types
and identifiers only.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from benchmarks import corpora

DEFAULT_DIR = corpora.EXTERNAL / "realworld"

# Canonical types, shared with the other corpora so the harness scores them alike.
TYPES = frozenset(
    {
        "SECRET",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "US_SSN",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION",
        "ORGANIZATION",
        "ID",
        "USERNAME",
        "URL",
        "DATE_TIME",
        "IBAN_CODE",
        "CRYPTO",
        "MAC_ADDRESS",
        "OTHER",
    }
)
NECESSITY = frozenset({"mandatory", "contextual"})
PROVENANCE_KEYS = (
    "description",
    "authorisation",
    "licence_or_agreement",
    "ethics_review",
    "collected",
    "live_secret_handling",
)


@dataclass(slots=True)
class Span:
    start: int
    end: int
    type: str
    subtype: str | None = None
    necessity: str = "mandatory"


@dataclass(slots=True)
class Document:
    doc_id: str
    text: str
    source: str
    kind: str


@dataclass(slots=True)
class Dataset:
    directory: Path
    provenance: dict[str, Any]
    documents: list[Document]
    annotations: dict[str, dict[str, list[Span]]]  # annotator -> doc_id -> spans
    adjudicated: dict[str, list[Span]] | None
    issues: list[str] = field(default_factory=list)


def data_dir() -> Path:
    return Path(os.environ.get("SAFESTREAM_REALWORLD_DIR", DEFAULT_DIR))


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{n}: not valid JSON ({exc.msg})") from None
    return rows


def _spans(
    rows: list[dict[str, Any]], texts: dict[str, str], where: str, issues: list[str]
) -> dict[str, list[Span]]:
    out: dict[str, list[Span]] = {}
    for row in rows:
        doc_id = row.get("doc_id")
        if doc_id not in texts:
            issues.append(f"{where}: unknown doc_id {doc_id!r}")
            continue
        if doc_id in out:
            issues.append(f"{where}: {doc_id} appears twice")
            continue
        n = len(texts[doc_id])
        spans = []
        for k, s in enumerate(row.get("spans", [])):
            tag = f"{where}: {doc_id} span {k}"
            start, end, typ = s.get("start"), s.get("end"), s.get("type")
            if not (isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= n):
                issues.append(f"{tag}: offsets {start}-{end} outside 0..{n} or empty")
                continue
            if typ not in TYPES:
                issues.append(f"{tag}: type {typ!r} not in the canonical set")
                continue
            necessity = s.get("necessity", "mandatory")
            if necessity not in NECESSITY:
                issues.append(f"{tag}: necessity {necessity!r} not in {sorted(NECESSITY)}")
                continue
            spans.append(Span(start, end, typ, s.get("subtype"), necessity))
        out[doc_id] = sorted(spans, key=lambda x: (x.start, x.end))
    for doc_id in texts.keys() - out.keys():
        issues.append(f"{where}: no line for {doc_id} (an empty 'spans' list means 'nothing')")
    return out


def load_dataset(directory: Path | None = None) -> Dataset:
    """Read and validate the corpus; problems are collected in ``issues``, not raised."""
    d = directory or data_dir()
    issues: list[str] = []
    if not d.is_dir():
        raise FileNotFoundError(f"{d} not found; see benchmarks/realworld/README.md")
    prov_path = d / "provenance.json"
    provenance: dict[str, Any] = {}
    if prov_path.exists():
        provenance = json.loads(prov_path.read_text(encoding="utf-8"))
        for key in PROVENANCE_KEYS:
            value = provenance.get(key)
            if not isinstance(value, str) or not value.strip():
                issues.append(f"provenance.json: '{key}' is missing or empty")
    else:
        issues.append("provenance.json is missing: record who authorised this data first")

    documents = []
    seen: set[str] = set()
    for n, row in enumerate(_jsonl(d / "documents.jsonl"), 1):
        doc_id, text = row.get("doc_id"), row.get("text")
        if not isinstance(doc_id, str) or not doc_id or not isinstance(text, str):
            issues.append(f"documents.jsonl:{n}: needs a string doc_id and text")
            continue
        if doc_id in seen:
            issues.append(f"documents.jsonl:{n}: duplicate doc_id {doc_id}")
            continue
        seen.add(doc_id)
        source = row.get("source")
        if not isinstance(source, str) or not source:
            issues.append(f"documents.jsonl:{n}: {doc_id} has no 'source' (the cluster unit)")
            source = "unknown"
        documents.append(Document(doc_id, text, source, str(row.get("kind", "unspecified"))))
    texts = {doc.doc_id: doc.text for doc in documents}

    annotations = {}
    ann_dir = d / "annotations"
    for path in sorted(ann_dir.glob("*.jsonl")) if ann_dir.is_dir() else []:
        annotations[path.stem] = _spans(_jsonl(path), texts, f"annotations/{path.name}", issues)
    if len(annotations) < 2:
        issues.append(f"{len(annotations)} annotator file(s); double annotation needs two")

    adjudicated = None
    if (d / "adjudicated.jsonl").exists():
        adjudicated = _spans(_jsonl(d / "adjudicated.jsonl"), texts, "adjudicated.jsonl", issues)
    return Dataset(d, provenance, documents, annotations, adjudicated, issues)


def summary(ds: Dataset) -> dict[str, Any]:
    """Counts only: safe to print or commit."""
    gold = ds.adjudicated or {}
    types: Counter[str] = Counter()
    subtypes: Counter[str] = Counter()
    for spans in gold.values():
        for s in spans:
            types[s.type] += 1
            if s.subtype:
                subtypes[f"{s.type}:{s.subtype}"] += 1
    return {
        "n_docs": len(ds.documents),
        "n_chars": sum(len(doc.text) for doc in ds.documents),
        "sources": dict(Counter(doc.source for doc in ds.documents)),
        "kinds": dict(Counter(doc.kind for doc in ds.documents)),
        "annotators": {
            name: sum(len(v) for v in spans.values()) for name, spans in ds.annotations.items()
        },
        "adjudicated": ds.adjudicated is not None,
        "gold_types": dict(types),
        "gold_subtypes": dict(subtypes),
        "gold_free_docs": sum(1 for doc in ds.documents if not gold.get(doc.doc_id)),
        "issues": ds.issues,
    }


def to_corpus(ds: Dataset) -> corpora.Corpus:
    """The adjudicated gold as a harness corpus. Refuses unvalidated or unadjudicated data."""
    if ds.issues:
        raise ValueError(
            "the real-world corpus has validation issues; run "
            "`python -m benchmarks.realworld validate` and fix them:\n  " + "\n  ".join(ds.issues)
        )
    if ds.adjudicated is None:
        raise ValueError("adjudicated.jsonl is missing: scores need adjudicated gold")
    docs = [
        corpora.Doc(
            doc.doc_id,
            doc.text,
            [corpora.Gold(s.start, s.end, s.type, s.necessity) for s in ds.adjudicated[doc.doc_id]],
        )
        for doc in ds.documents
    ]
    sources = [ds.directory / "documents.jsonl", ds.directory / "adjudicated.jsonl"]
    revision = ds.provenance.get("collected")
    note = "authorised real-world artefacts; " + str(ds.provenance.get("description", ""))
    return corpora.Corpus("realworld", docs, sources, revision, note)


def sources_of(doc_ids: list[str], directory: Path | None = None) -> list[str]:
    """The cluster label (``source``) of each document, in the order given."""
    rows = {r["doc_id"]: r for r in _jsonl((directory or data_dir()) / "documents.jsonl")}
    return ["source:" + str(rows[i].get("source", "unknown")) for i in doc_ids]
