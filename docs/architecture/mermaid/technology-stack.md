# Technology Stack

Layered technology view: interfaces, application engines, the concrete
detection techniques, the runtime, and supported deployment targets.

> Validated against `pyproject.toml` (Python 3.10–3.13, zero third-party
> runtime deps in the core; spaCy is the optional `[ner]` extra) and
> `detectors/` (regex + validators, Shannon entropy, contextual heuristics).

```mermaid
flowchart TB
    subgraph Presentation["PRESENTATION LAYER"]
        CLI["CLI<br/>Command Line Interface"]
        API["Python Library API<br/>+ optional REST API"]
    end
    subgraph Application["APPLICATION LAYER"]
        Stream["Streaming Engine"]
        Detect["Detection Engine"]
        Redact["Redaction Engine"]
    end
    subgraph Core["CORE COMPONENTS / LIBRARIES"]
        Regex["Regex + Validators"]
        Entropy["Shannon Entropy Scoring"]
        Spacy["spaCy NER<br/>(optional [ner] extra)"]
        Context["Contextual Heuristics"]
    end
    subgraph Runtime["RUNTIME LAYER"]
        Python["Python 3.10 - 3.13"]
    end
    subgraph Deployment["DEPLOYMENT LAYER"]
        Docker["Docker"]
        Linux["Linux"]
        Windows["Windows"]
        Mac["macOS"]
    end

    CLI --> Stream
    API --> Stream
    Stream --> Detect
    Detect --> Regex
    Detect --> Entropy
    Detect --> Spacy
    Detect --> Context
    Detect --> Redact
    Stream --> Python
    Detect --> Python
    Redact --> Python
    Python --> Docker
    Python --> Linux
    Python --> Windows
    Python --> Mac
```
