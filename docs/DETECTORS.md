# Detectors

SafeStream uses a four-tier detector cascade. Every detection is a
`Detection` (`entities.py`) carrying a span, entity type, confidence, and source
tier; overlaps are resolved most-specific/highest-confidence wins.

## Tiers

| Tier | Module | What it does |
| --- | --- | --- |
| 1. Deterministic | `detectors/deterministic.py` | Anchored regexes + validators (Luhn, `ipaddress`, SSN rules). Highest precision. |
| 2. Statistical | `detectors/entropy.py` | High-entropy tokens with no published format (bespoke keys, session tokens). |
| 3. NER (optional) | `detectors/ner.py` | spaCy PERSON/ORG/LOC. Requires the `ner` extra + a model. |
| 4. Contextual | `detectors/contextual.py` | Nudges confidence from surrounding trigger words; promotes trigger-gated spans (bare SSN next to "ssn:"). |

Custom words/regexes (`detectors/custom.py`) and third-party plugins
(entry-point group `safestream_redactor.detectors`) plug in alongside these.

## Coverage and severity

Severity (`severity.py`) drives SARIF levels and MCP output. It is a static
property of the type, never of the matched text.

| Severity | Entity types |
| --- | --- |
| critical | `aws_key`, `aws_secret`, `private_key`, `github_token`, `slack_token`, `stripe_key`, `openai_key`, `anthropic_key`, `sendgrid_key`, `twilio_key`, `npm_token`, `google_api_key` |
| high | `slack_webhook`, `jwt`, `api_key`, `url_credentials`, `secret`, `ssn`, `credit_card` |
| medium | `email`, `phone`, `person`, `custom` |
| low | `ipv4`, `ipv6`, `org`, `loc` |

## Streaming requirements

Each detector declares a `StreamingRequirements` (`detectors/base.py`): the
longest span it can emit (`max_span`) and the left/right context it reads. The
engine derives its overlap from the maximum across the active detectors
(`engine.required_overlap`), so a detector's declared `max_span` is what
guarantees a boundary-split entity of that length is still seen whole. Setting an
overlap below the aggregate requirement logs a coverage warning.

| Detector | max_span | left/right context |
| --- | --- | --- |
| deterministic | 8192 | 0 / 0 |
| entropy | 8192 | 0 / 0 |
| contextual | 9 | 48 / 0 |
| custom | 8192 | 0 / 0 |
| ner | 256 | 256 / 256 |

## Adding a detector

Use the `add-a-detector` workflow (`.claude/skills/add-a-detector/`), which walks
through: entity type + severity, an anchored and span-bounded pattern with a
validator, positive and **hard-negative** fixtures (UUIDs, git hashes, version
strings, base64 — the look-alikes that must not fire), a boundary-split test, and
the `pytest`/`ruff`/`mypy`/benchmark gates. Never weaken existing detection or a
threshold to make a new pattern look good.
