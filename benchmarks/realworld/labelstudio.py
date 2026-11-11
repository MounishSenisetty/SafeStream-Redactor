"""Convert a Label Studio JSON export into the real-world corpus layout.

Each task's ``data`` must hold ``text``; ``doc_id``, ``source`` and ``kind`` are
used when present (``doc_id`` falls back to ``ls-<task id>``; a missing ``source``
is reported by ``validate``). Each non-cancelled annotation becomes one annotator
file, named by Label Studio user id (``annotator-<id>``), never by e-mail address.
Labels map to canonical types through ``label_map`` (identity for canonical names);
an unmapped label is kept as-is and reported by ``validate``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _annotator(ann: dict[str, Any]) -> str:
    who = ann.get("completed_by")
    uid = who.get("id") if isinstance(who, dict) else who
    return f"annotator-{uid}"


def convert(
    export: list[dict[str, Any]], out_dir: Path, label_map: dict[str, str] | None = None
) -> dict[str, int]:
    """Write ``documents.jsonl`` and ``annotations/<annotator>.jsonl``; return counts."""
    label_map = label_map or {}
    docs: list[dict[str, Any]] = []
    per_annotator: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for task in export:
        data = task.get("data", {})
        doc_id = str(data.get("doc_id") or f"ls-{task.get('id')}")
        row = {"doc_id": doc_id, "text": data.get("text", "")}
        row |= {k: data[k] for k in ("source", "kind") if k in data}
        docs.append(row)
        for ann in task.get("annotations", []):
            if ann.get("was_cancelled"):
                continue
            spans = []
            for r in ann.get("result", []):
                v = r.get("value", {})
                if r.get("type") != "labels" or "start" not in v:
                    continue
                for label in v.get("labels", []):
                    typ, _, sub = label_map.get(label, label).partition(":")
                    span = {"start": v["start"], "end": v["end"], "type": typ}
                    if sub:
                        span["subtype"] = sub
                    spans.append(span)
            per_annotator.setdefault(_annotator(ann), {})[doc_id] = spans
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "annotations").mkdir(exist_ok=True)
    with (out_dir / "documents.jsonl").open("w", encoding="utf-8") as f:
        for row in docs:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    for name, by_doc in per_annotator.items():
        with (out_dir / "annotations" / f"{name}.jsonl").open("w", encoding="utf-8") as f:
            for row in docs:  # every document, so a skipped one shows up as an issue
                if row["doc_id"] in by_doc:
                    line = {"doc_id": row["doc_id"], "spans": by_doc[row["doc_id"]]}
                    f.write(json.dumps(line) + "\n")
    return {"documents": len(docs), "annotators": len(per_annotator)}
