# Level-1 Data Flow Diagram

Decomposition of process (0) into its seven internal processes: chunk reader,
window manager, detection engine, score/filter/resolve, redaction policy,
atomic output writer, and stats/report.

> Validated against `engine.py` (1–2, 6), `redactor.py:detect` +
> `detectors/` (3), `entities.py:resolve_overlaps` + contextual/calibration (4),
> `policy.py` (5), `report.py` (7).

```mermaid
flowchart TD
    Input[("Input file / stream")]
    P1["1 — Chunk reader"]
    P2["2 — Window manager<br/>(rolling buffer + overlap)"]
    P3["3 — Detection engine<br/>(multi-tier cascade)"]
    P4["4 — Score • filter • resolve"]
    P5["5 — Redaction policy<br/>(render + apply)"]
    P6["6 — Atomic output writer"]
    P7["7 — Stats / report"]
    Report[("Content-free report")]
    Output[("Redacted output")]

    Input --> P1
    P1 --> P2
    P2 -->|"overlap margin"| P3
    P3 --> P4
    P4 --> P5
    P5 --> P6
    P6 --> Output
    P4 -->|"categories + counts"| P7
    P7 --> Report
```
