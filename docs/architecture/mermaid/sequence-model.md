# File-Redaction Sequence

The canonical sequence for redacting a file: the facade opens a restricted-access
temporary output, streams window-by-window through detection → arbitration →
policy, writes each redacted window, and finally replaces the output atomically.

> Validated against `redactor.py:redact_file` (temp file via `mkstemp`,
> streaming loop, `os.replace` atomic commit) and `cli.py`.

```mermaid
sequenceDiagram
    actor Operator
    participant CLI
    participant Facade as Facade (Redactor)
    participant Stream as Streaming engine
    participant Detect as Detection Tiers
    participant Arb as Arbitration
    participant Policy as Redaction policy
    participant FS as File system

    Operator->>CLI: redact input → output [options]
    CLI->>Facade: redact_file(input, output)
    Facade->>FS: open temporary output (restricted access)
    loop For each chunk until input exhausted
        Stream->>Stream: Read next window (buffer + overlap)
        Stream->>Detect: detect(window text)
        Detect-->>Stream: candidate detections
        Stream->>Arb: adjust / filter / resolve
        Arb-->>Stream: final non-overlapping detections
        Stream->>Policy: apply(window, detections)
        Policy-->>Stream: redacted window
        Stream->>FS: write redacted window
        Stream->>Stream: retain overlap margin
    end
    Facade->>FS: atomically replace output with temporary file
    Facade->>CLI: RedactionStats(counts, sizes)
    CLI->>Operator: summary + exit status
```
