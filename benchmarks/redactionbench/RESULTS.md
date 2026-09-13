# RedactionBench — measured results for SafeStream-Redactor

Real numbers from running the **shipped** SafeStream-Redactor pipeline over the full Hugging Face `RedactionBench/RedactionBench` dataset. Reproduce with the commands at the bottom; nothing here is estimated.

> **Deep audit & why the score is what it is:** see [`AUDIT.md`](AUDIT.md). Summary:
> the harness is verified correct (offsets, matching, aggregation, streaming=whole
> all check out — no false failures); the low all-gold F1 is driven by RedactionBench's
> subjective `contextual` class (57% of gold characters, ~47.7% human agreement,
> mostly single characters/date-separators) plus person names (45% of mandatory misses,
> NER-bound). A **label-anchored identifier cascade** was added to the core as a genuine,
> precision-safe improvement (mandatory recall 0.686→0.691 core / 0.765→0.769 with NER,
> precision held, streaming byte-identical). **A near-1.0 score on this dataset is not
> defensible for a precision-respecting streaming redactor** — the audit explains why in
> detail (methodology section 7).

## Setup

- **Dataset**: `RedactionBench/RedactionBench` · revision `d45e9cec89bc49c69355e252fec29cc0229982f6` · 200 documents, 11 domains
- **SafeStream version**: 0.4.0 · prediction mode: **streaming** (constant-memory engine, chunk=4096) · min_confidence=0.5
- **Python** 3.11.15 · Linux-6.18.44-fc-v24-x86_64-with-glibc2.39
- **Task**: RedactionBench labels every span by *necessity* (`mandatory`/`contextual`), not by PII type, so this is a **binary redaction** evaluation scored with the dataset's character-level **R-Score** methodology (formatting-agnostic). Per-PII-type precision/recall is **not computable** from this dataset.
- **Streaming = whole-document**: the constant-memory chunked engine produces **byte-for-byte identical** character metrics to whole-document processing on all 200 documents (chunk-boundary correctness, verified in the run).

## Headline: character-level coverage (R-Score style)

| Configuration | Char precision | Char recall | Char F1 (95% CI) | Char accuracy | Mandatory recall | Contextual recall | No-mandatory-leak docs |
|---|--:|--:|--:|--:|--:|--:|--:|
| Core (regex+validators+entropy, **no NER**) | 0.753 | 0.401 | 0.524 [0.462, 0.569] | 0.895 | 0.686 | 0.185 | 0.125 |
| Core **+ spaCy NER** (`--ner`) | 0.544 | 0.531 | 0.538 [0.450, 0.607] | 0.869 | 0.765 | 0.354 | 0.175 |

**Reading these numbers.** *Char precision/recall/F1* are per-character over the whole redaction mask. *Mandatory recall* is the fraction of must-redact characters that were hidden — the DLP-critical number. NER raises recall (names/free-text) at a cost to precision (more over-redaction); the core favours precision. *No-mandatory-leak docs* is the fraction of documents with **every** mandatory character redacted — a strict per-document accuracy, distinct from precision/recall.

## Span-level, type-agnostic (secondary)

| Configuration | Precision | Recall | F1 | TP | FP | FN |
|---|--:|--:|--:|--:|--:|--:|
| Core (no NER) | 0.728 | 0.095 | 0.167 | 5033 | 1878 | 48253 |
| Core + NER | 0.329 | 0.137 | 0.194 | 7313 | 14886 | 45973 |

_Span precision is low **by construction**: RedactionBench segments one value into many adjacent mandatory/contextual spans, while SafeStream emits one span per entity, so a single prediction can 1:1-match only one gold fragment. Character coverage above is the faithful measure; these span numbers are included for completeness._

## Per-domain character coverage (core, no NER)

| Domain | Docs | Char P | Char R | Char F1 | Mandatory recall |
|---|--:|--:|--:|--:|--:|
| academic | 16 | 0.657 | 0.043 | 0.080 | 0.135 |
| code | 16 | 0.764 | 0.619 | 0.684 | 0.711 |
| emails | 16 | 0.931 | 0.334 | 0.492 | 0.345 |
| files | 36 | 0.687 | 0.474 | 0.561 | 0.658 |
| financial | 18 | 0.960 | 0.103 | 0.186 | 0.142 |
| government | 16 | 0.923 | 0.056 | 0.106 | 0.096 |
| legal | 18 | 0.875 | 0.024 | 0.047 | 0.056 |
| logs | 17 | 0.802 | 0.461 | 0.585 | 0.855 |
| medical | 16 | 0.448 | 0.056 | 0.099 | 0.078 |
| operations | 15 | 0.924 | 0.143 | 0.248 | 0.105 |
| terminal | 16 | 0.711 | 0.577 | 0.637 | 0.799 |

SafeStream's core is strongest on structured/credential-dense domains (code, terminal, logs, files, emails) and weakest on name/free-text-heavy ones (academic, legal, medical, government) — where the `--ner` tier helps most (e.g. academic mandatory recall 0.135 → 0.691 with NER).

## What SafeStream predicted (by type)

The dataset has no gold PII types, so per-type recall can't be scored; this is the distribution of the **predictions'** types (core run):

| Type | Predicted spans |
|---|--:|
| ipv4 | 3115 |
| secret | 1849 |
| email | 1090 |
| phone | 250 |
| api_key | 154 |
| jwt | 146 |
| aws_key | 78 |
| url_credentials | 58 |
| stripe_key | 46 |
| ssn | 38 |
| credit_card | 36 |
| ipv6 | 21 |

## Reproduce

```bash
pip install -e '.[redactionbench]'   # datasets + huggingface_hub + pyarrow
# dataset staged in benchmarks/data/redactionbench/ (revision in REVISION); or add --download

# core (shipped pipeline, no NER):
python -m benchmarks.redactionbench.run run \
    --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench

# with the optional spaCy NER tier:
pip install -e '.[ner]' && python -m spacy download en_core_web_sm
python -m benchmarks.redactionbench.run run --ner \
    --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench-ner
```

_Full methodology in [README.md](README.md). Raw predictions, results.json, and per-domain CSVs are regenerated into `benchmarks/results/` (git-ignored). Generated 2026-09-12._
