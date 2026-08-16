# SafeStream-Redactor — Architecture Diagrams

This directory holds the **canonical, editable source** for every architecture
diagram, as [Mermaid](./mermaid/) and (where a second notation adds value)
[PlantUML](./plantuml/). The diagrams were recreated from the original system
design document and then **validated against the implementation** — the table
below maps each diagram to the code it describes so the two cannot silently
drift apart.

Rendered images, if needed, should be generated from these sources (e.g.
`mmdc` for Mermaid, `plantuml` for `.puml`) rather than hand-drawn, so the
source stays the single point of truth.

## Diagram index

| Diagram | Mermaid | PlantUML | Primary source in code |
|---|---|---|---|
| Overall system architecture | [overall-system-architecture.md](./mermaid/overall-system-architecture.md) | — | `redactor.py`, `engine.py`, `cli.py` |
| Component model | [component-model.md](./mermaid/component-model.md) | [component-model.puml](./plantuml/component-model.puml) | `redactor.py`, `detectors/`, `netguard.py`, `scheduler.py` |
| Class / structural model | [class-model.md](./mermaid/class-model.md) | [class-model.puml](./plantuml/class-model.puml) | `entities.py`, `policy.py`, `report.py`, `redactor.py`, `detectors/` |
| Technology stack | [technology-stack.md](./mermaid/technology-stack.md) | — | `pyproject.toml`, `detectors/` |
| Rolling buffer / overlap window | [rolling-buffer.md](./mermaid/rolling-buffer.md) | — | `engine.py` (`stream_windows`, `stream_transform`) |
| Multi-tier detection cascade | [detection-cascade.md](./mermaid/detection-cascade.md) | — | `redactor.py:detect`, `detectors/`, `entities.py:resolve_overlaps` |
| Deployment model | [deployment-model.md](./mermaid/deployment-model.md) | [deployment-model.puml](./plantuml/deployment-model.puml) | `pyproject.toml`, `Dockerfile`, CI workflows |
| File-redaction sequence | [sequence-model.md](./mermaid/sequence-model.md) | [sequence-model.puml](./plantuml/sequence-model.puml) | `redactor.py:redact_file`, `cli.py` |
| Redaction activity / workflow | [activity-model.md](./mermaid/activity-model.md) | [activity-model.puml](./plantuml/activity-model.puml) | `cli.py`, `engine.py`, `redactor.py` |
| Context-level DFD | [context-dfd.md](./mermaid/context-dfd.md) | — | `cli.py`, `netguard.py`, `report.py` |
| Level-1 DFD | [level-1-dfd.md](./mermaid/level-1-dfd.md) | — | `engine.py`, `redactor.py`, `policy.py`, `report.py` |
| REST API | [rest-api.md](./mermaid/rest-api.md) | — | `api.py`, `redactor.py` |

## Validation notes (implementation is the source of truth)

The diagrams were checked against the code on the current branch. Corrections
applied while importing them:

- **Class model — `EntityType`.** The implementation enumerates more credential
  types than the original figure (see `entities.py`): in addition to
  `EMAIL/PHONE/CREDIT_CARD/SSN/IPV4/AWS_KEY/GITHUB_TOKEN/JWT/PRIVATE_KEY/URL/…`
  it includes `IPV6`, `AWS_SECRET`, `API_KEY`, `SLACK_TOKEN`, `SLACK_WEBHOOK`,
  `STRIPE_KEY`, `GOOGLE_API_KEY`, `SENDGRID_KEY`, `TWILIO_KEY`, `NPM_TOKEN`,
  `OPENAI_KEY`, `ANTHROPIC_KEY`, and `URL_CREDENTIALS` (the URL-userinfo
  password). The diagram now reflects the real enum.
- **Class model — `Detection`.** The dataclass carries `text` and a `meta`
  dict in addition to `start/end/entity_type/confidence/source` (`entities.py`).
- **Class model — `RedactionStats`.** Real fields are `counts`, `chars_in`,
  `chars_out`, and `decode_replacements`, with `total`, `add_segment`, `merge`,
  and `summary` (`report.py`).
- **REST API** was added to match the `api.py` module (loopback-only, stdlib
  HTTP server that forwards to the same `Redactor`).

Everything else in the original diagram set matched the implementation and was
preserved as-is.
