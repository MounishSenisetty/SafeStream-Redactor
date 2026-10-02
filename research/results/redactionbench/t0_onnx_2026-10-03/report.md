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
| all gold | 0.682 | 0.537 | 0.601 | 0.897 | 205764 | 96138 | 177698 |
| mandatory (read recall) | — | **0.815** | — | — | 134656 | — | 30583 |
| contextual (read recall) | — | 0.326 | — | — | 71108 | — | 147115 |

- **Character-F1 (all gold)**: 0.601  (95% bootstrap CI [0.538, 0.644])
- **Mandatory character recall** (must-redact coverage): 0.815
- **Contextual character recall**: 0.326
- **No-mandatory-leak document rate**: 0.180  (documents with every mandatory character redacted; per-document, not P/R/F1)

## Span-level (type-agnostic, ≥overlap match)

| Subset | Precision | Recall | F1 | TP | FP | FN |
|---|--:|--:|--:|--:|--:|--:|
| all gold | 0.493 | 0.146 | 0.226 | 7802 | 8038 | 45484 |
| mandatory | 0.348 | 0.324 | 0.336 | 5509 | 10331 | 11484 |
| contextual | 0.364 | 0.159 | 0.221 | 5765 | 10075 | 30528 |

_Span precision is low by construction: SafeStream emits one span per detected entity, while gold segments a value into many adjacent mandatory/contextual spans, so one prediction can only 1:1-match one of them. Character coverage above is the faithful measure._

## Per domain

| Domain | Docs | Char P | Char R | Char F1 | Mandatory char recall | Span F1 |
|---|--:|--:|--:|--:|--:|--:|
| academic | 16 | 0.594 | 0.381 | 0.464 | 0.831 | 0.197 |
| code | 16 | 0.656 | 0.696 | 0.675 | 0.801 | 0.443 |
| emails | 16 | 0.798 | 0.516 | 0.627 | 0.680 | 0.249 |
| files | 36 | 0.631 | 0.566 | 0.597 | 0.739 | 0.263 |
| financial | 18 | 0.692 | 0.396 | 0.503 | 0.611 | 0.184 |
| government | 16 | 0.652 | 0.382 | 0.482 | 0.645 | 0.157 |
| legal | 18 | 0.399 | 0.344 | 0.369 | 0.651 | 0.198 |
| logs | 17 | 0.770 | 0.559 | 0.648 | 0.926 | 0.216 |
| medical | 16 | 0.414 | 0.427 | 0.420 | 0.724 | 0.181 |
| operations | 15 | 0.811 | 0.455 | 0.583 | 0.633 | 0.256 |
| terminal | 16 | 0.709 | 0.617 | 0.659 | 0.861 | 0.283 |

## What SafeStream predicted (by entity type)

The dataset has no gold PII types, so this is the distribution of the **predictions'** types (not scored against gold types).

| SafeStream type | predicted spans |
|---|--:|
| org | 3478 |
| loc | 3212 |
| ipv4 | 3115 |
| secret | 1938 |
| person | 1565 |
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
python -m benchmarks.redactionbench.run run --out-dir research/results/redactionbench/t0_onnx_2026-10-03 --onnx-model models/ner/model.int8.onnx --onnx-vocab models/ner/tokenizer.json --onnx-labels models/ner/labels.json
```

_Environment_: Python 3.14.0, Windows-11-10.0.26200-SP0, run took 383.51s.