# Multi-Tier Detection Cascade

Each window of text is scanned by every enabled tier in parallel; the raw
detections are pooled, contextually adjusted, filtered by confidence threshold,
and reduced to a non-overlapping set by overlap resolution.

> Validated against `redactor.py:detect` (pool → `ContextualScorer.adjust` →
> optional `Calibrator` → `min_confidence` filter → `resolve_overlaps`),
> `detectors/deterministic.py`, `detectors/entropy.py`, `detectors/ner.py`,
> `detectors/custom.py`, `detectors/registry.py` (plugins), and
> `entities.py:resolve_overlaps` (most-specific + most-confident wins).

```mermaid
flowchart LR
    Window["Window text<br/>+ retained left context"]
    T1["Tier 1 — Deterministic<br/>pattern recognition + validation"]
    T2["Tier 2 — Entropy<br/>Shannon entropy scoring"]
    T3["Tier 3 — NER (optional)<br/>pre-trained model"]
    T4["Custom words / regex"]
    T5["Third-party plugin tiers"]
    Pool["Raw detections"]
    Context["Contextual adjustment<br/>boost / suppress / promote"]
    Filter["Confidence filter<br/>≥ threshold"]
    Resolve["Overlap resolution<br/>most specific + confident"]
    Final["Final detections"]

    Window --> T1
    Window --> T2
    Window --> T3
    Window --> T4
    Window --> T5
    T1 --> Pool
    T2 --> Pool
    T3 --> Pool
    T4 --> Pool
    T5 --> Pool
    Pool --> Context
    Context --> Filter
    Filter --> Resolve
    Resolve --> Final
```
