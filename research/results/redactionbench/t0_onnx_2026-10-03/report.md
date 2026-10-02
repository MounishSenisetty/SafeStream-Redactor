# RedactionBench results — SafeStream-Redactor

- **Dataset**: `RedactionBench/RedactionBench`  ·  source: vendored files in benchmarks\data\redactionbench
- **Revision**: `d45e9cec89bc49c69355e252fec29cc0229982f6`
- **Task**: binary redaction (necessity: mandatory/contextual) — RedactionBench R-Score style
- **Documents scored**: 200  (parsed 200 of 200 raw rows)
- **SafeStream version**: 0.4.0  ·  mode: **streaming**  ·  chunk=4096  ·  min_confidence=0.5  ·  NER=False
- **Detector tiers**: deterministic, labeled_identifier, onnx, entropy, compound_secret, contextual
- **Span match**: ≥50% overlap, type-agnostic (dataset has no PII types)

> RedactionBench annotates each span by **necessity** (mandatory vs contextual), not by PII type, so this is a **binary redaction** evaluation — did the system hide the characters that must be hidden? The character-level metric follows the dataset's R-Score methodology (formatting-agnostic). Per-PII-type recall is **not computable** from this dataset; the predicted-type distribution is reported instead.

## Character-level coverage (R-Score style)

| Subset | Precision | Recall | F1 | Accuracy | char TP | char FP | char FN |
|---|--:|--:|--:|--:|--:|--:|--:|
| all gold | 0.685 | 0.545 | 0.607 | 0.898 | 209105 | 96328 | 174357 |
| mandatory (read recall) | — | **0.823** | — | — | 135937 | — | 29302 |
| contextual (read recall) | — | 0.335 | — | — | 73168 | — | 145055 |

- **Character-F1 (all gold)**: 0.607  (95% bootstrap CI [0.548, 0.650])
- **Mandatory character recall** (must-redact coverage): 0.823
- **Contextual character recall**: 0.335
- **No-mandatory-leak document rate**: 0.215  (documents with every mandatory character redacted; per-document, not P/R/F1)

## Span-level (type-agnostic, ≥overlap match)

| Subset | Precision | Recall | F1 | TP | FP | FN |
|---|--:|--:|--:|--:|--:|--:|
| all gold | 0.493 | 0.147 | 0.226 | 7823 | 8043 | 45463 |
| mandatory | 0.348 | 0.325 | 0.336 | 5515 | 10351 | 11478 |
| contextual | 0.377 | 0.165 | 0.229 | 5975 | 9891 | 30318 |

_Span precision is low by construction: SafeStream emits one span per detected entity, while gold segments a value into many adjacent mandatory/contextual spans, so one prediction can only 1:1-match one of them. Character coverage above is the faithful measure._

## Per domain

| Domain | Docs | Char P | Char R | Char F1 | Mandatory char recall | Span F1 |
|---|--:|--:|--:|--:|--:|--:|
| academic | 16 | 0.612 | 0.405 | 0.487 | 0.857 | 0.198 |
| code | 16 | 0.655 | 0.695 | 0.674 | 0.800 | 0.442 |
| emails | 16 | 0.802 | 0.528 | 0.637 | 0.700 | 0.249 |
| files | 36 | 0.631 | 0.567 | 0.597 | 0.739 | 0.264 |
| financial | 18 | 0.711 | 0.432 | 0.537 | 0.690 | 0.187 |
| government | 16 | 0.663 | 0.417 | 0.512 | 0.695 | 0.156 |
| legal | 18 | 0.446 | 0.420 | 0.433 | 0.781 | 0.205 |
| logs | 17 | 0.770 | 0.560 | 0.648 | 0.927 | 0.216 |
| medical | 16 | 0.423 | 0.458 | 0.440 | 0.752 | 0.174 |
| operations | 15 | 0.834 | 0.512 | 0.635 | 0.719 | 0.257 |
| terminal | 16 | 0.709 | 0.617 | 0.659 | 0.861 | 0.283 |

## What SafeStream predicted (by entity type)

The dataset has no gold PII types, so this is the distribution of the **predictions'** types (not scored against gold types).

| SafeStream type | predicted spans |
|---|--:|
| org | 3473 |
| ipv4 | 3115 |
| loc | 2847 |
| secret | 1934 |
| person | 1579 |
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
python -m benchmarks.redactionbench.run run --out-dir research/results/redactionbench/t0_onnx_2026-10-03 --onnx-model models/ner/model.int8.onnx --onnx-vocab models/ner/tokenizer.json --onnx-labels models/ner/labels.json
```

_Environment_: Python 3.14.0, Windows-11-10.0.26200-SP0, run took 156.227s.