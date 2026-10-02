# RedactionBench results — SafeStream-Redactor

- **Dataset**: `RedactionBench/RedactionBench`  ·  source: vendored files in benchmarks\data\redactionbench
- **Revision**: `d45e9cec89bc49c69355e252fec29cc0229982f6`
- **Task**: binary redaction (necessity: mandatory/contextual) — RedactionBench R-Score style
- **Documents scored**: 200  (parsed 200 of 200 raw rows)
- **SafeStream version**: 0.4.0  ·  mode: **streaming**  ·  chunk=4096  ·  min_confidence=0.5  ·  NER=False
- **Detector tiers**: deterministic, labeled_identifier, entropy, compound_secret, contextual
- **Span match**: ≥50% overlap, type-agnostic (dataset has no PII types)

> RedactionBench annotates each span by **necessity** (mandatory vs contextual), not by PII type, so this is a **binary redaction** evaluation — did the system hide the characters that must be hidden? The character-level metric follows the dataset's R-Score methodology (formatting-agnostic). Per-PII-type recall is **not computable** from this dataset; the predicted-type distribution is reported instead.

## Character-level coverage (R-Score style)

| Subset | Precision | Recall | F1 | Accuracy | char TP | char FP | char FN |
|---|--:|--:|--:|--:|--:|--:|--:|
| all gold | 0.767 | 0.447 | 0.565 | 0.901 | 171504 | 52221 | 211958 |
| mandatory (read recall) | — | **0.759** | — | — | 125392 | — | 39847 |
| contextual (read recall) | — | 0.211 | — | — | 46112 | — | 172111 |

- **Character-F1 (all gold)**: 0.565  (95% bootstrap CI [0.509, 0.614])
- **Mandatory character recall** (must-redact coverage): 0.759
- **Contextual character recall**: 0.211
- **No-mandatory-leak document rate**: 0.140  (documents with every mandatory character redacted; per-document, not P/R/F1)

## Span-level (type-agnostic, ≥overlap match)

| Subset | Precision | Recall | F1 | TP | FP | FN |
|---|--:|--:|--:|--:|--:|--:|
| all gold | 0.735 | 0.110 | 0.191 | 5854 | 2113 | 47432 |
| mandatory | 0.573 | 0.269 | 0.366 | 4565 | 3402 | 12428 |
| contextual | 0.555 | 0.122 | 0.200 | 4426 | 3541 | 31867 |

_Span precision is low by construction: SafeStream emits one span per detected entity, while gold segments a value into many adjacent mandatory/contextual spans, so one prediction can only 1:1-match one of them. Character coverage above is the faithful measure._

## Per domain

| Domain | Docs | Char P | Char R | Char F1 | Mandatory char recall | Span F1 |
|---|--:|--:|--:|--:|--:|--:|
| academic | 16 | 0.815 | 0.099 | 0.176 | 0.258 | 0.054 |
| code | 16 | 0.774 | 0.669 | 0.718 | 0.776 | 0.489 |
| emails | 16 | 0.938 | 0.377 | 0.538 | 0.417 | 0.148 |
| files | 36 | 0.699 | 0.513 | 0.592 | 0.718 | 0.241 |
| financial | 18 | 0.974 | 0.191 | 0.319 | 0.381 | 0.083 |
| government | 16 | 0.931 | 0.166 | 0.281 | 0.346 | 0.060 |
| legal | 18 | 0.949 | 0.155 | 0.266 | 0.340 | 0.089 |
| logs | 17 | 0.804 | 0.491 | 0.610 | 0.907 | 0.230 |
| medical | 16 | 0.656 | 0.171 | 0.271 | 0.244 | 0.070 |
| operations | 15 | 0.957 | 0.264 | 0.413 | 0.361 | 0.120 |
| terminal | 16 | 0.715 | 0.596 | 0.650 | 0.830 | 0.271 |

## What SafeStream predicted (by entity type)

The dataset has no gold PII types, so this is the distribution of the **predictions'** types (not scored against gold types).

| SafeStream type | predicted spans |
|---|--:|
| ipv4 | 3115 |
| secret | 1934 |
| email | 1092 |
| address | 341 |
| phone | 259 |
| id_number | 218 |
| aws_account_id | 213 |
| mac_address | 159 |
| api_key | 154 |
| jwt | 146 |
| aws_key | 78 |
| url_credentials | 58 |
| stripe_key | 46 |
| ssn | 38 |
| credit_card | 37 |
| dob | 28 |
| ipv6 | 21 |
| slack_webhook | 10 |
| github_token | 6 |
| openai_key | 5 |
| aws_secret | 4 |
| slack_token | 2 |
| sendgrid_key | 1 |
| anthropic_key | 1 |
| private_key | 1 |

## Reproduce

```bash
python -m benchmarks.redactionbench.run run --out-dir research/results/redactionbench/t0_2026-10-03
```

_Environment_: Python 3.14.0, Windows-11-10.0.26200-SP0, run took 10.791s.