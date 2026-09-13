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
| `predictions.jsonl` | one line per document: gold spans (offsets + necessity), every raw prediction (offset, SafeStream type, confidence, tier), and that document's scores |
| `results.json` | full metrics: overall (character + span, split by necessity), per domain, plus run metadata (dataset revision, resolved fields, config, predicted-type distribution, failed samples, environment, command) |
| `per_domain.csv` | per-domain character + span P/R/F1 and mandatory-recall + an OVERALL row (spreadsheet-friendly) |
| `report.md` | the concise human report (also printed to stdout) |

(For a PII-typed corpus the outputs are instead `per_type.csv` and a per-entity-type report — see *Two scoring modes* below.)

## What RedactionBench actually contains

Each record is `raw_text` plus a list of `spans`, where every span is
`{start, end, label}` and **`label` is a *necessity* class — `mandatory` or
`contextual` — not a PII entity type.** RedactionBench is grounded in *contextual
integrity*: it marks which character ranges must (mandatory) or may, depending on
context (contextual), be redacted, rather than tagging entities as
email/person/etc. The dataset's own metric, **R-Score**, is therefore
**character-level and formatting-agnostic** — it asks whether the right
*characters* were hidden, not whether a replacement string matched.

Because there is **no per-PII-type gold**, per-entity-type precision/recall is
**not computable** against this dataset (the harness says so and reports the
distribution of the *predictions'* types instead). This is a property of the
dataset, not a limitation of the tool.

## Methodology

### Preprocessing
Each record is normalised to `(doc_id, raw_text, [spans], category)`. A span is
`(start, end, necessity)` in **character** offsets; spans out of text bounds are
dropped (RedactionBench has none). The `croissant.json` metadata sidecar is
skipped. No text is altered before it reaches the redactor — the document is fed
to the pipeline verbatim.

### Running the real pipeline
In `streaming` mode (default) the document is chunked and passed to
`Redactor.detect_stream`, i.e. the constant-memory rolling-buffer engine.
`detect_stream` yields `(segment, detections)` with **segment-relative** offsets;
the adapter accumulates the emitted segment lengths to lift every detection back
into absolute document coordinates, and asserts the segments reconstruct the
document exactly. This makes **chunk-boundary** behaviour part of the measurement
— an entity split across a chunk is scored at its true position. `whole` mode
calls `Redactor.detect` on the full string; the two modes are verified to produce
**byte-for-byte identical** character metrics on the full corpus.

### Two scoring modes
The harness auto-detects which kind of gold labels a corpus carries
(`--gold-label-kind auto`, override with `necessity` or `pii_type`):

- **Necessity mode (RedactionBench).** Binary redaction — "redact vs keep". No
  per-type scoring.
- **PII-type mode (Presidio/CoNLL-style corpora).** Per-entity-type scoring with a
  label map. Kept for reuse on other datasets.

### Necessity-mode metrics (what RedactionBench is scored with)
Not exact-string comparison. Two families, each split by necessity:

1. **Character-level coverage (R-Score methodology).** A per-character redaction
   mask for gold vs predictions → per-character precision/recall/F1 and accuracy.
   This nullifies masking-style differences (`[REDACTED]` vs `***` vs `<PHONE>`)
   exactly as R-Score intends. It is a faithful character-level *reimplementation
   of the methodology*, **not** a call into the paper's official scorer (not
   bundled) — the report labels it as such. Reported for **all** gold, and as
   **recall** for the **mandatory** and **contextual** subsets separately
   (precision is only meaningful on the full mask).
2. **Span-level, type-agnostic P/R/F1.** A prediction hits a gold span when it
   covers ≥ `--overlap-threshold` (default 50%) of it; greedy one-to-one. Recall =
   gold redaction spans covered; precision = predictions landing on a gold span.
   Reported for all / mandatory / contextual. Span **precision is low by
   construction** because gold segments one value into many adjacent
   mandatory/contextual spans while SafeStream emits one span per entity — so
   character coverage is the faithful measure, and the span numbers are secondary.

### Mandatory protection (a per-document accuracy)
`mandatory_protection.no_leak_document_rate` is the fraction of **documents**
where **every mandatory character was redacted** (no must-redact leak) — a
per-document DLP accuracy, reported **separately** from precision/recall/F1
(which are per-character or per-span rates) and not to be conflated with them.

### Confidence interval
`results.json` → `overall.character_level_rscore_style.char_f1_all_bootstrap_ci_95`
is a 95% bootstrap CI on all-gold character-F1, resampling whole documents (1000
resamples, seed 0).

### Names / free text
SafeStream's shipped core (regex + validators + entropy) targets structured PII
and credentials; names, addresses and other free-text spans need the optional
`--ner` tier. Both configurations are reported in [`RESULTS.md`](RESULTS.md).

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
- Necessity split: mandatory and contextual spans are scored both together (all
  gold) and separately. Contextual redactions are inherently subjective — the
  RedactionBench paper reports low human agreement on them (~47.7%) versus high
  agreement on mandatory (~89.4%) — so the **mandatory** numbers are the more
  stable signal; contextual recall is expected to be lower for any system.
- Span-level precision understates real precision (gold over-segments each value
  into adjacent spans vs one prediction per entity); read character coverage as
  the faithful precision/recall.
- All numbers depend on the resolved schema — check the `inspect` output and
  `results.json → metadata.resolved_fields` before quoting.

## Dependencies

- Core scoring on `.jsonl`/`.json`/`.csv` exports: **no extra deps** (stdlib +
  the installed `safestream_redactor`).
- Reading `.parquet` or `--download`: `pip install -e '.[redactionbench]'`.
- NER tier: `pip install -e '.[ner]'` + `python -m spacy download en_core_web_sm`.
