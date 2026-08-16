# Component Model

Runtime components inside the single local process, and the two external actors
(a human operator and an automated CI pipeline) that invoke it.

> Validated against `cli.py`, `redactor.py` (facade), `config.py`,
> `netguard.py` (egress safeguard), `engine.py` (streaming), `detectors/`
> (tiers + plugins via `detectors/registry.py`), `entities.py:resolve_overlaps`
> (arbitration), `policy.py`, `report.py` (run report / stats),
> `scheduler.py` / `parallel.py` (scheduler).

```mermaid
flowchart TB
    Operator(["Operator"])
    Pipeline(["CI / Automated pipeline"])
    subgraph SSR["SafeStream-Redactor (single local process)"]
        Scheduler["Scheduler"]
        CLI["Command-line interface"]
        Facade["Programmatic facade"]
        Config["Configuration"]
        Egress["Egress safeguard"]
        Stream["Streaming engine"]
        Detector["Detector"]
        Custom["Custom / plugin tiers"]
        Deterministic["Deterministic tier"]
        Entropy["Entropy tier"]
        NER["NER tier (optional)"]
        Contextual["Contextual tier"]
        Arbitration["Arbitration<br/>(score • filter • resolve)"]
        Policy["Redaction policy"]
        Stats["Run report / stats"]
    end
    FS[("Local file system")]

    Operator --> CLI
    Pipeline --> CLI
    Scheduler --> CLI
    CLI --> Facade
    CLI --> Config
    Egress -. "blocks non-loopback egress" .-> Stream
    Facade --> Stream
    Config --> Facade
    Stream --> Detector
    Detector --> Custom
    Detector --> Deterministic
    Detector --> Entropy
    Detector --> NER
    Detector --> Contextual
    Custom --> Arbitration
    Deterministic --> Arbitration
    Entropy --> Arbitration
    NER --> Arbitration
    Contextual --> Arbitration
    Arbitration --> Policy
    Policy --> Stream
    Stream --> Stats
    Stats --> FS
    Stream --> FS
```
