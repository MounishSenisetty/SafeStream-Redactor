# RedactionBench evaluation harness

A reproducible benchmark that measures the **shipped** SafeStream-Redactor
architecture against the Hugging Face
[`RedactionBench/RedactionBench`](https://huggingface.co/datasets/RedactionBench/RedactionBench)
dataset — 200 manually-annotated documents across 11 domains, grounded in
contextual integrity (Mireshghallah et al., *RedactionBench*, arXiv:2606.18782).

The harness is **isolated from the core**: it lives entirely under
`benchmarks/redactionbench/` and only calls the public
`safestream_redactor` API (`Redactor.detect` / `detect_stream`). It changes no
detector, threshold, or pattern — the goal is to measure the architecture as
it is, not to tune it to the benchmark.

```
benchmarks/redactionbench/
├── loader.py   dataset acquisition (HF download OR vendored files) + schema inspection
├── adapter.py  RedactionBench record  ⇄  SafeStream input / predictions  (+ label map)
├── metrics.py  span-level P/R/F1, character-level R-Score-style coverage, dataset accuracy
└── run.py      the CLI:  `inspect`  and  `run`
```

## 1. Get the dataset

The dataset lives on Hugging Face. Two supported paths:

### A. Direct download (needs network access to `huggingface.co`)

```bash
pip install -e '.[redactionbench]'          # datasets + huggingface_hub + pyarrow
python -m benchmarks.redactionbench.run run --download \
    --out-dir benchmarks/results/redactionbench
```

The resolved commit sha is recorded in `results.json` → `metadata.dataset.revision`
so the exact revision is captured.

### B. Vendored files (network-restricted environments)

Download the dataset **elsewhere** and stage the files in
`benchmarks/data/redactionbench/`, then point the harness at that directory
(the default). Any mix of `.parquet` / `.jsonl` / `.json` / `.csv` is read.

```bash
# on a machine with HF access:
huggingface-cli download RedactionBench/RedactionBench --repo-type dataset \
    --local-dir redactionbench_export
git -C <hf-cache> rev-parse HEAD   # capture the revision

# copy the data files into the repo and record the revision:
cp redactionbench_export/*.parquet benchmarks/data/redactionbench/
echo "<commit-sha>" > benchmarks/data/redactionbench/REVISION
```

`REVISION` (a plain sha on one line) is picked up and echoed into the results
metadata, keeping vendored runs as reproducible as direct downloads.

## 2. Inspect the schema (always do this first)

RedactionBench, like most PII corpora, does not publish one fixed column layout,
so the loader is **schema-adaptive** and tells you exactly what it resolved:

```bash
python -m benchmarks.redactionbench.run inspect --data-dir benchmarks/data/redactionbench
```

It prints: the raw top-level keys and their value types, a few sample rows, the
field the loader chose for text / spans / start / end / type / id / domain, and
a per-category count showing which dataset labels map onto SafeStream entity
types and which are **unsupported** (SafeStream ships no detector for them).

If auto-detection picks the wrong field, pin it explicitly — every field has a
`--*-key` override (`--text-key`, `--spans-key`, `--start-key`, `--end-key`,
`--type-key`, `--id-key`, `--domain-key`, `--redacted-text-key`,
`--necessity-key`), and category mapping is overridable with `--label-map`.

## 3. Run the benchmark

```bash
# structured PII + credentials, streaming (constant-memory) engine, no NER
python -m benchmarks.redactionbench.run run \
    --data-dir benchmarks/data/redactionbench \
    --out-dir  benchmarks/results/redactionbench

# add the optional spaCy NER tier so PERSON/ORG/LOC can be detected
pip install -e '.[ner]' && python -m spacy download en_core_web_sm
python -m benchmarks.redactionbench.run run --ner \
    --data-dir benchmarks/data/redactionbench \
    --out-dir  benchmarks/results/redactionbench-ner
```

Useful flags: `--mode {streaming,whole}` (default `streaming`),
`--chunk-size N` (small values deliberately stress chunk boundaries),
`--overlap-threshold F` (span-match strictness, default 0.5),
`--min-confidence F`, `--types a,b,c`, `--limit N`, `--label-map SRC=dst,...`.

## Outputs

Written to `--out-dir`:

| File | Contents |
|---|---|
| `predictions.jsonl` | one line per document: gold spans (+ mapped type + necessity), every raw prediction (offset, type, confidence, tier), and that document's scores |
| `results.json` | full metrics: overall, per entity type, per domain, plus the run metadata (dataset revision, resolved fields, config, unsupported categories, failed samples, environment, command) |
| `per_type.csv` | per-entity-type TP/FP/FN/P/R/F1 + a MICRO row (spreadsheet-friendly) |
| `report.md` | the concise human report (also printed to stdout) |

## Methodology

### Preprocessing
Each record is normalised to `(doc_id, text, [spans], domain?)`. A span is
`(start, end, category)` in **character** offsets into `text`; spans whose end
exceeds the text length are dropped (logged in `load_skipped`). No text is
altered before it reaches the redactor — the document is fed to the pipeline
verbatim.

### Running the real pipeline
In `streaming` mode (default) the document is chunked and passed to
`Redactor.detect_stream`, i.e. the constant-memory rolling-buffer engine.
`detect_stream` yields `(segment, detections)` with **segment-relative** offsets;
the adapter accumulates the emitted segment lengths to lift every detection back
into absolute document coordinates, and asserts the segments reconstruct the
document exactly. This is what makes the **chunk-boundary** behaviour part of the
measurement rather than an afterthought — an entity split across a chunk is
scored at its true position. `whole` mode calls `Redactor.detect` on the full
string and is used as a cross-check (the two modes agree on the shipped tiers).

### Matching predictions to ground truth
Not exact-string comparison. Three complementary families are reported and kept
separate because they answer different questions:

1. **Span-level P/R/F1 (type-aware)** — a prediction hits a gold span when it
   overlaps ≥ `--overlap-threshold` (default 50%) of that gold span and the
   predicted SafeStream type equals the mapped gold type; matching is greedy and
   one-to-one. Reported per type, plus **micro** (pooled counts) and **macro**
   (unweighted mean of per-type F1). This credits partial / differently-bounded
   spans, which exact-match would not.
2. **Span-level, type-agnostic** — the same overlap match ignoring the label:
   "did we flag the right *location*?" Useful because SafeStream may detect the
   right span under a different (but still sensitive) type.
3. **Character-level coverage (R-Score-style)** — RedactionBench's own metric,
   R-Score, is character-level and formatting-agnostic. We reproduce that
   methodology with a per-character redaction mask (gold vs predicted) and score
   per-character precision/recall/F1 and accuracy. This nullifies masking-style
   differences (`[REDACTED]` vs `***` vs `<PHONE>`) exactly as R-Score intends.
   It is a faithful character-level *reimplementation of the methodology*, **not**
   a call into the paper's official scorer (not bundled) — the report labels it
   as such. Reported in two scopes: **supported** (gold mask from mapped-type
   spans only) and **all-gold** (gold mask from every gold span, the honest
   total-coverage recall including categories SafeStream cannot detect).

### Dataset-level accuracy vs precision/recall/F1
`dataset_level_accuracy.exact_document_rate` is the fraction of **documents**
whose predicted redaction mask exactly equals the supported-scope gold mask — a
per-document accuracy. It is reported **separately** from precision/recall/F1
(which are per-span or per-character rates) and must not be conflated with them.

### Unsupported categories
A category the dataset annotates but SafeStream ships no detector for is
**excluded from type-aware precision/recall** — counting it as a miss would
penalise the tool for something it never claims to detect — but it is listed in
the report and **is** included in the all-gold character-coverage recall, so
total coverage stays honest. Names/orgs/locations require `--ner`; without it
they show up as recall misses on the `person`/`org`/`loc` rows.

### Confidence interval
`results.json` → `overall.span_level.micro_f1_bootstrap_ci_95` is a 95% bootstrap
CI on micro-F1, resampling whole documents (1000 resamples, seed 0).

## Limitations

- The harness measures SafeStream's shipped tiers. Its regex/validator/entropy
  core targets structured PII and credentials; free-form PII (names, addresses,
  org names) needs the optional `--ner` tier, and format-less identifiers
  (account/passport/employee IDs) need label-anchored custom patterns
  (`examples/policy.toml`) — otherwise they are recall misses by design.
- The character-level metric follows the R-Score *methodology* (character mask,
  formatting-agnostic) but is not the paper's exact scorer; treat it as a
  faithful reimplementation, and if the official scorer is later vendored the
  harness can call it directly.
- Contextual-integrity labels: if the dataset distinguishes *mandatory* from
  *contextual* redactions, the necessity flag is preserved per span
  (`predictions.jsonl`) but the headline metrics score all annotated spans
  together; a mandatory-only slice can be added once the real field is confirmed
  via `inspect`.
- All numbers depend on the resolved schema and label map — check the
  `inspect` output and `results.json → metadata.resolved_fields` before quoting.

## Dependencies

- Core scoring on `.jsonl`/`.json`/`.csv` exports: **no extra deps** (stdlib +
  the installed `safestream_redactor`).
- Reading `.parquet` or `--download`: `pip install -e '.[redactionbench]'`.
- NER tier: `pip install -e '.[ner]'` + `python -m spacy download en_core_web_sm`.
