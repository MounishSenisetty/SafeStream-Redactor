# Redaction Activity / Workflow

End-to-end control flow of a run: validate configuration, build tiers, install
the egress safeguard, then loop chunk-by-chunk (retreating the boundary when it
would split a detection) until the input is exhausted, commit atomically, and
emit a content-free report.

> Validated against `cli.py` (config validation, egress guard install),
> `engine.py` (window loop, overlap carry-forward, boundary retreat),
> `redactor.py:redact_file` (temp write + atomic commit), and `report.py`.

```mermaid
flowchart TD
    Start((Start))
    ReadPolicy["Read policy file (if any)"]
    Valid{"Configuration valid?"}
    Reject["Reject with suggestion"]
    EndFail((End))
    Overlay["Overlay explicit options on policy"]
    Build["Build detector tiers + policy"]
    Egress["Install egress safeguard (default on)"]
    Read["Read next chunk into buffer"]
    Enough{"buffer ≤ overlap?"}
    Carry["Carry forward, emit nothing"]
    Detect["Run multi-tier detection on window"]
    Adjust["Adjust • filter • resolve"]
    Split{"Boundary splits a detection?"}
    Retreat["Retreat boundary to entity start"]
    Apply["Apply redaction policy"]
    Write["Write redacted segment to temp file"]
    Retain["Retain overlap margin as left context"]
    More{"More input?"}
    Commit["Atomically replace output with temp file"]
    Report["Emit content-free stats / report"]
    End((End))

    Start --> ReadPolicy
    ReadPolicy --> Valid
    Valid -- No --> Reject
    Reject --> EndFail
    Valid -- Yes --> Overlay
    Overlay --> Build
    Build --> Egress
    Egress --> Read
    Read --> Enough
    Enough -- Yes --> Carry
    Carry --> Read
    Enough -- No --> Detect
    Detect --> Adjust
    Adjust --> Split
    Split -- Yes --> Retreat
    Retreat --> Apply
    Split -- No --> Apply
    Apply --> Write
    Write --> Retain
    Retain --> More
    More -- Yes --> Read
    More -- No --> Commit
    Commit --> Report
    Report --> End
```
