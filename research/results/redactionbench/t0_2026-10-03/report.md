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
| all gold | 0.760 | 0.430 | 0.549 | 0.898 | 164758 | 52021 | 218704 |
| mandatory (read recall) | — | **0.739** | — | — | 122023 | — | 43216 |
| contextual (read recall) | — | 0.196 | — | — | 42735 | — | 175488 |

- **Character-F1 (all gold)**: 0.549  (95% bootstrap CI [0.488, 0.599])
- **Mandatory character recall** (must-redact coverage): 0.739
- **Contextual character recall**: 0.196
- **No-mandatory-leak document rate**: 0.140  (documents with every mandatory character redacted; per-document, not P/R/F1)

## Span-level (type-agnostic, ≥overlap match)

| Subset | Precision | Recall | F1 | TP | FP | FN |
|---|--:|--:|--:|--:|--:|--:|
| all gold | 0.724 | 0.103 | 0.180 | 5488 | 2097 | 47798 |
| mandatory | 0.575 | 0.257 | 0.355 | 4359 | 3226 | 12634 |
| contextual | 0.536 | 0.112 | 0.185 | 4068 | 3517 | 32225 |

_Span precision is low by construction: SafeStream emits one span per detected entity, while gold segments a value into many adjacent mandatory/contextual spans, so one prediction can only 1:1-match one of them. Character coverage above is the faithful measure._

## Per domain

| Domain | Docs | Char P | Char R | Char F1 | Mandatory char recall | Span F1 |
|---|--:|--:|--:|--:|--:|--:|
| academic | 16 | 0.694 | 0.051 | 0.095 | 0.183 | 0.032 |
| code | 16 | 0.774 | 0.669 | 0.718 | 0.776 | 0.489 |
| emails | 16 | 0.933 | 0.350 | 0.509 | 0.377 | 0.133 |
| files | 36 | 0.699 | 0.511 | 0.591 | 0.718 | 0.240 |
| financial | 18 | 0.961 | 0.123 | 0.218 | 0.201 | 0.054 |
| government | 16 | 0.939 | 0.076 | 0.140 | 0.146 | 0.034 |
| legal | 18 | 0.793 | 0.026 | 0.050 | 0.063 | 0.016 |
| logs | 17 | 0.804 | 0.491 | 0.609 | 0.906 | 0.230 |
| medical | 16 | 0.525 | 0.085 | 0.146 | 0.167 | 0.045 |
| operations | 15 | 0.927 | 0.150 | 0.258 | 0.119 | 0.071 |
| terminal | 16 | 0.715 | 0.596 | 0.650 | 0.830 | 0.271 |

## What SafeStream predicted (by entity type)

The dataset has no gold PII types, so this is the distribution of the **predictions'** types (not scored against gold types).

| SafeStream type | predicted spans |
|---|--:|
| ipv4 | 3115 |
| secret | 1938 |
| email | 1092 |
| phone | 254 |
| aws_account_id | 213 |
| id_number | 182 |
| mac_address | 159 |
| api_key | 154 |
| jwt | 146 |
| aws_key | 78 |
| url_credentials | 58 |
| stripe_key | 46 |
| ssn | 38 |
| credit_card | 37 |
| dob | 24 |
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

_Environment_: Python 3.14.0, Windows-11-10.0.26200-SP0, run took 14.746s.