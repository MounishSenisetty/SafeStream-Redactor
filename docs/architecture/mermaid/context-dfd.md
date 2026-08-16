# Context-Level Data Flow Diagram

The system as a single process (0) and the external entities it exchanges data
with. Off-machine network access is blocked by the egress safeguard.

> Validated against `cli.py` (command/options, policy file, input),
> `report.py` (content-free run report), `netguard.py` (blocked egress).

```mermaid
flowchart LR
    Operator["Operator"]
    CI["CI / pipeline"]
    Policy["Policy file"]
    Input[("Input file / stream")]
    System["SafeStream-Redactor (0)"]
    Output[("Redacted output")]
    Report[("Content-free run report")]
    Network["Off-machine network"]

    Operator -->|"command + options"| System
    CI -->|"invoke as gate"| System
    Policy -->|"policy"| System
    Input -->|"text"| System
    System -->|"redacted text"| Output
    System -->|"counts + sizes"| Report
    System -. "blocked" .-> Network
```
