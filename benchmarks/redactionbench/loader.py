"""Load the RedactionBench dataset and normalise it into records.

Two acquisition paths, in priority order:

1. **Vendored files** under a local directory (default
   ``benchmarks/data/redactionbench/``). Any mix of ``.parquet``, ``.jsonl``,
   ``.json`` and ``.csv`` files is read and concatenated. This is the path used
   in network-restricted environments: download the dataset elsewhere with
   ``huggingface-cli download RedactionBench/RedactionBench --repo-type dataset``
   (or ``datasets``' ``save_to_disk`` / ``to_parquet``), commit the files, and
   point the harness at the directory.
2. **Direct Hugging Face download** with ``--download`` (needs the ``datasets``
   library and outbound access to ``huggingface.co``). The exact resolved
   revision (commit sha) is recorded in the run metadata so results are
   reproducible.

RedactionBench, like most PII corpora, does not publish a single fixed column
layout across its splits/configs, so the loader is **schema-adaptive**: it
resolves the document text and the ground-truth spans from a set of candidate
field names, all of which can be overridden on the CLI once you have inspected
the real schema (``rb inspect``). Nothing about the resolution is silent — the
resolver records which key it used for every field, and ``inspect`` prints them.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Candidate field names, most specific first. Overridable via FieldSpec so that
# once the real schema is known it can be pinned exactly rather than guessed.
TEXT_KEYS = (
    "raw_text",
    "text",
    "full_text",
    "document",
    "content",
    "input",
    "original_text",
    "original",
    "source_text",
    "body",
    "prompt",
    "context",
)
SPANS_KEYS = (
    "spans",
    "annotations",
    "entities",
    "labels",
    "pii_spans",
    "redactions",
    "ground_truth",
    "gt_spans",
    "targets",
)
# Within a span object:
START_KEYS = ("start", "start_position", "begin", "start_offset", "char_start", "startChar")
END_KEYS = ("end", "end_position", "stop", "end_offset", "char_end", "endChar")
LEN_KEYS = ("length", "len")
TYPE_KEYS = (
    "type",
    "entity_type",
    "label",
    "category",
    "tag",
    "pii_type",
    "entity",
    "class",
)
# Some corpora also carry a fully-redacted reference string; used for the
# character-level R-Score-style metric when present.
REDACTED_TEXT_KEYS = (
    "redacted_text",
    "redacted",
    "target",
    "target_text",
    "gold_text",
    "masked_text",
    "output",
)
# A per-span flag distinguishing mandatory from contextual redactions (a
# RedactionBench-specific concept). Recorded when present so metrics can be
# reported for the mandatory subset separately.
NECESSITY_KEYS = ("necessity", "required", "mandatory", "is_mandatory", "redaction_type", "kind")


@dataclass(frozen=True)
class Span:
    """A ground-truth annotated span (character offsets into the record text)."""

    start: int
    end: int
    label: str
    necessity: str | None = None  # e.g. "mandatory" / "contextual" when the dataset marks it

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span offsets: start={self.start} end={self.end}")


@dataclass
class RBRecord:
    """One RedactionBench document plus its ground-truth annotations."""

    doc_id: str
    text: str
    spans: list[Span]
    redacted_text: str | None = None
    domain: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class FieldSpec:
    """Overrides for schema resolution (all optional; empty means auto-detect)."""

    text_key: str | None = None
    spans_key: str | None = None
    start_key: str | None = None
    end_key: str | None = None
    type_key: str | None = None
    id_key: str | None = None
    domain_key: str | None = None
    redacted_text_key: str | None = None
    necessity_key: str | None = None


@dataclass
class LoadResult:
    records: list[RBRecord]
    source: str  # human description of where the data came from
    revision: str | None  # HF commit sha when downloaded, else None
    resolved_fields: dict[str, str | None]  # which key each field resolved to
    files: list[str] = field(default_factory=list)
    row_count: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)  # rows we could not parse


# ---------------------------------------------------------------------------
# raw-file readers (stdlib only for json/jsonl/csv; pyarrow/pandas for parquet)
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj


def _read_json(path: Path) -> Iterator[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # Either a single record, or a wrapper like {"data": [...]} / {"rows": [...]}.
        for wrapper in ("data", "rows", "records", "examples", "test", "train", "validation"):
            inner = data.get(wrapper)
            if isinstance(inner, list):
                yield from (r for r in inner if isinstance(r, dict))
                return
        yield data
    elif isinstance(data, list):
        yield from (r for r in data if isinstance(r, dict))


def _read_csv(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            yield dict(row)


def _read_parquet(path: Path) -> Iterator[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ImportError as e:  # pragma: no cover - environment dependent
        raise SystemExit(
            "reading .parquet needs pyarrow: pip install 'safestream-redactor[bench]' "
            "or pip install pyarrow"
        ) from e
    table = pq.read_table(path)
    for batch in table.to_pylist():
        if isinstance(batch, dict):
            yield batch


_READERS = {
    ".jsonl": _read_jsonl,
    ".json": _read_json,
    ".csv": _read_csv,
    ".parquet": _read_parquet,
}


def _iter_raw_rows(files: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in files:
        reader = _READERS.get(path.suffix.lower())
        if reader is None:
            continue
        yield from reader(path)


# Metadata/sidecar files a Hugging Face dataset snapshot ships that are NOT data
# rows and must not be parsed as records (Croissant metadata, dataset-info, etc.).
SKIP_BASENAMES = frozenset(
    {"croissant.json", "dataset_infos.json", "dataset_dict.json", "state.json"}
)


def discover_files(directory: Path) -> list[Path]:
    """All readable dataset files under ``directory`` (recursively), sorted.

    Skips known metadata sidecars (e.g. ``croissant.json``) so they are not
    mistaken for data rows.
    """
    out: list[Path] = []
    for suffix in _READERS:
        out.extend(directory.rglob(f"*{suffix}"))
    return sorted(p for p in set(out) if p.name.lower() not in SKIP_BASENAMES)


# ---------------------------------------------------------------------------
# schema resolution
# ---------------------------------------------------------------------------


def _first_present(row: dict[str, Any], keys: Iterable[str], override: str | None) -> str | None:
    if override is not None:
        return override if override in row else None
    for k in keys:
        if k in row:
            return k
    return None


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_span(obj: Any, spec: FieldSpec, default_label: str) -> Span | None:
    """Turn one raw annotation into a Span, or None if it cannot be parsed."""
    if not isinstance(obj, dict):
        return None
    start_key = _first_present(obj, START_KEYS, spec.start_key)
    end_key = _first_present(obj, END_KEYS, spec.end_key)
    if start_key is None:
        return None
    start = _coerce_int(obj[start_key])
    if start is None:
        return None
    if end_key is not None:
        end = _coerce_int(obj[end_key])
    else:  # start + length form
        len_key = _first_present(obj, LEN_KEYS, None)
        length = _coerce_int(obj[len_key]) if len_key else None
        end = start + length if length is not None else None
    if end is None or end < start:
        return None
    type_key = _first_present(obj, TYPE_KEYS, spec.type_key)
    label = str(obj[type_key]) if type_key else default_label
    nec_key = _first_present(obj, NECESSITY_KEYS, spec.necessity_key)
    necessity = str(obj[nec_key]) if nec_key else None
    return Span(start=start, end=end, label=label, necessity=necessity)


def resolve_record(
    row: dict[str, Any], spec: FieldSpec, index: int
) -> tuple[RBRecord | None, dict[str, str | None], str | None]:
    """Resolve one raw row into an RBRecord.

    Returns ``(record, resolved_keys, error)``. ``record`` is None when the row
    lacks usable text or spans, in which case ``error`` explains why.
    """
    resolved: dict[str, str | None] = {}
    text_key = _first_present(row, TEXT_KEYS, spec.text_key)
    resolved["text"] = text_key
    if text_key is None or not isinstance(row[text_key], str):
        return None, resolved, "no text field resolved"
    text = row[text_key]

    id_key = spec.id_key if (spec.id_key and spec.id_key in row) else None
    if id_key is None:
        for k in ("id", "doc_id", "document_id", "uid", "index", "name"):
            if k in row:
                id_key = k
                break
    resolved["id"] = id_key
    doc_id = str(row[id_key]) if id_key else f"doc_{index}"

    domain_key = _first_present(row, ("domain", "category", "source", "genre"), spec.domain_key)
    resolved["domain"] = domain_key
    domain = str(row[domain_key]) if domain_key else None

    redtxt_key = _first_present(row, REDACTED_TEXT_KEYS, spec.redacted_text_key)
    resolved["redacted_text"] = redtxt_key
    redacted_text = row[redtxt_key] if redtxt_key and isinstance(row[redtxt_key], str) else None

    spans_key = _first_present(row, SPANS_KEYS, spec.spans_key)
    resolved["spans"] = spans_key
    spans: list[Span] = []
    if spans_key is not None:
        raw_spans = row[spans_key]
        # Datasets stored as HF "Sequence of struct" arrive as a dict of parallel
        # lists ({"start": [...], "end": [...], "type": [...]}); normalise that
        # into a list of per-span dicts first.
        if isinstance(raw_spans, dict) and all(isinstance(v, list) for v in raw_spans.values()):
            n = max((len(v) for v in raw_spans.values()), default=0)
            raw_spans = [
                {k: (v[i] if i < len(v) else None) for k, v in raw_spans.items()} for i in range(n)
            ]
        if isinstance(raw_spans, list):
            for obj in raw_spans:
                span = _extract_span(obj, spec, default_label="pii")
                if span is not None and span.end <= len(text):
                    spans.append(span)

    if spans_key is None and redacted_text is None:
        return None, resolved, "no spans or redacted-text field resolved"

    return (
        RBRecord(
            doc_id=doc_id,
            text=text,
            spans=spans,
            redacted_text=redacted_text,
            domain=domain,
            raw=row,
        ),
        resolved,
        None,
    )


# ---------------------------------------------------------------------------
# top-level load
# ---------------------------------------------------------------------------


def load_from_directory(directory: Path, spec: FieldSpec) -> LoadResult:
    files = discover_files(directory)
    if not files:
        raise SystemExit(
            f"no dataset files (.parquet/.jsonl/.json/.csv) found under {directory}. "
            "Stage the RedactionBench export there (see benchmarks/redactionbench/README.md)."
        )
    records: list[RBRecord] = []
    skipped: list[dict[str, Any]] = []
    resolved_fields: dict[str, str | None] = {}
    n = 0
    for row in _iter_raw_rows(files):
        rec, resolved, err = resolve_record(row, spec, n)
        n += 1
        if not resolved_fields:  # keep the first successful resolution map
            resolved_fields = resolved
        if rec is None:
            if len(skipped) < 50:
                skipped.append({"index": n - 1, "reason": err, "keys": sorted(row)[:20]})
            continue
        resolved_fields = resolved
        records.append(rec)
    return LoadResult(
        records=records,
        source=f"vendored files in {directory}",
        revision=_read_revision(directory),
        resolved_fields=resolved_fields,
        files=[str(f) for f in files],
        row_count=n,
        skipped=skipped,
    )


def _read_revision(directory: Path) -> str | None:
    """Read a pinned revision sha from a REVISION file if the user staged one."""
    for name in ("REVISION", "revision.txt", ".revision"):
        p = directory / name
        if p.is_file():
            return p.read_text(encoding="utf-8").strip() or None
    return None


def download_from_hf(
    repo_id: str, revision: str | None, spec: FieldSpec, cache_dir: Path | None = None
) -> LoadResult:  # pragma: no cover - requires network + datasets
    """Download the dataset directly from Hugging Face (needs `datasets`)."""
    try:
        from datasets import get_dataset_config_names, load_dataset
    except ImportError as e:
        raise SystemExit("--download needs the 'datasets' library: pip install datasets") from e
    from huggingface_hub import HfApi

    api = HfApi()
    info = api.dataset_info(repo_id, revision=revision)
    resolved_rev = info.sha

    configs = get_dataset_config_names(repo_id, revision=revision)
    records: list[RBRecord] = []
    skipped: list[dict[str, Any]] = []
    resolved_fields: dict[str, str | None] = {}
    n = 0
    for config in configs or [None]:
        ds = load_dataset(
            repo_id, name=config, revision=revision, cache_dir=str(cache_dir) if cache_dir else None
        )
        for split in ds:
            for row in ds[split]:
                rec, resolved, err = resolve_record(dict(row), spec, n)
                n += 1
                if rec is None:
                    if len(skipped) < 50:
                        skipped.append({"index": n - 1, "reason": err, "config": config})
                    continue
                resolved_fields = resolved
                records.append(rec)
    return LoadResult(
        records=records,
        source=f"huggingface:{repo_id}@{resolved_rev}",
        revision=resolved_rev,
        resolved_fields=resolved_fields,
        files=[],
        row_count=n,
        skipped=skipped,
    )


# ---------------------------------------------------------------------------
# schema inspection (for the `inspect` CLI subcommand)
# ---------------------------------------------------------------------------


def inspect_raw(directory: Path, sample: int = 3) -> dict[str, Any]:
    """Summarise the raw files without committing to a schema resolution.

    Prints the union of top-level keys, per-key value-type histogram, and a few
    sample rows (truncated) so the true schema can be pinned via --*-key flags.
    """
    files = discover_files(directory)
    key_counter: Counter[str] = Counter()
    key_types: dict[str, Counter[str]] = {}
    samples: list[dict[str, Any]] = []
    total = 0
    for row in _iter_raw_rows(files):
        total += 1
        for k, v in row.items():
            key_counter[k] += 1
            key_types.setdefault(k, Counter())[type(v).__name__] += 1
        if len(samples) < sample:
            samples.append({k: _truncate(v) for k, v in row.items()})
    return {
        "directory": str(directory),
        "files": [str(f) for f in files],
        "rows": total,
        "top_level_keys": {k: dict(key_types[k]) for k, _ in key_counter.most_common()},
        "sample_rows": samples,
    }


def _truncate(value: Any, limit: int = 300) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"...(+{len(value) - limit} chars)"
    if isinstance(value, list) and len(value) > 5:
        return [*value[:5], f"...(+{len(value) - 5} items)"]
    return value
