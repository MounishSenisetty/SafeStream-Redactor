# Overall System Architecture

Layered view of the whole system. Interfaces and supporting facilities feed a
single coordination point, which drives the streaming engine; the engine fans
window text out to the detection tiers, whose arbitrated results are rewritten
by the transformation layer and written to the local file system.

> Validated against `cli.py` / `redactor.py` (interfaces + coordination),
> `engine.py` (streaming), `detectors/` (detection tiers), `policy.py`
> (transformation), `netguard.py` (egress safeguard), `report.py`
> (content-free auditing). The stray "Context-free auditing" node from the
> original figure was dropped — it corresponds to no component.

```mermaid
flowchart TB
    subgraph Interface["Interface Layer"]
        CLI["Command-line interface"]
        API["Programmatic interface"]
    end
    subgraph Supporting["Supporting Facilities"]
        Config["Configuration"]
        Scheduler["Parallel scheduling"]
        Audit["Content-free auditing"]
        Egress["Egress safeguard"]
    end
    subgraph Coordination["Coordination Layer"]
        Task["Unified point of control<br/>(detection tiers + policy)"]
    end
    subgraph Processing["Processing Layer"]
        Stream["Streaming engine<br/>rolling buffer + overlap window"]
    end
    subgraph Detection["Detection Layer"]
        Det["Deterministic<br/>recognition + validation"]
        Entropy["Statistical<br/>entropy analysis"]
        NER["Linguistic recognition<br/>(optional NER)"]
        Contextual["Contextual reasoning"]
        Arb["Confidence arbitration<br/>+ overlap resolution"]
    end
    subgraph Transformation["Transformation Layer"]
        Redact["Policy-governed rewriting<br/>substitute / mask / pseudonymise"]
    end
    Local["Local file system<br/>(no database, no server)"]

    CLI --> Task
    API --> Task
    Config --> Task
    Task --> Stream
    Scheduler --> Stream
    Egress -.-> Stream
    Stream --> Det
    Stream --> Entropy
    Stream --> NER
    Stream --> Contextual
    Det --> Arb
    Entropy --> Arb
    NER --> Arb
    Contextual --> Arb
    Arb --> Redact
    Redact --> Local
    Stream --> Local
    Audit --> Local
    Egress -. "blocks non-loopback egress" .-> Local
```
