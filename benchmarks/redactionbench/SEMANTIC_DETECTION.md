# Semantic detection for SafeStream — implementation report

Moving from diagnosis to implementation: the forensic analysis
([`DIAGNOSIS.md`](DIAGNOSIS.md)) identified **person/organization names** (class
B / semantic, 0.014 recall in the deterministic core) as the dominant recoverable
recall gap. This report implements and measures semantic detectors that close it,
**inside the validated streaming architecture** (no chunking/boundary changes),
and quantifies the precision/utility/performance trade-off with a threshold sweep
and a benign false-positive set.

All numbers are measured on the full 200-document RedactionBench corpus (revision
`d45e9cec…`, streaming engine) plus a 20-document benign public-prose set
(`benchmarks/data/benign/`). Reproduce with
`python -m benchmarks.redactionbench.eval_configs --config <name> --benign`.

> Metric note (carried from [`VALIDATION.md`](VALIDATION.md)): the official
> R-Score is unreleased, so these are proxy character metrics; **mandatory recall**
> is the recall figure that matters, and contextual spans are *not* counted as
> required. No number here is an official R-Score.

## 1. Baseline vs final — the four configurations

| Config | PChar | RChar | F1 | **Mandatory** | benign FP | throughput | peak RSS | startup | p95 latency |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **A** core (shipped) | 0.753 | 0.404 | 0.526 | 0.691 | **0.000** | 467K ch/s | 157 MB | 0.02 s | 98 ms |
| **C** core + gazetteer | 0.731 | 0.437 | **0.547** | 0.720 | **0.000** | 239K ch/s | 161 MB | 0.02 s | 186 ms |
| **B** core + spaCy NER | 0.545 | 0.533 | 0.539 | 0.769 | 0.050 | 12K ch/s | 364 MB | 2.0 s | 4027 ms |
| **D** core + spaCy + gazetteer | 0.544 | 0.542 | 0.543 | **0.775** | 0.050 | 12K ch/s | 377 MB | 2.0 s | 4266 ms |

The **gazetteer (C) gives the best F1 (0.547)** with zero benign false positives
and negligible cost; the **NER configs (B/D) give the best mandatory recall
(0.77)** but at a large precision, utility, and performance cost.

## 2. Improvement attributable to semantic detection

Deltas vs the core baseline (A):

| | mandatory recall | name (B) recall | RChar | F1 | benign FP |
|---|--:|--:|--:|--:|--:|
| gazetteer (C) | **+0.029** (0.691→0.720) | **+0.326** (0.014→0.340) | +0.033 | +0.021 | +0.000 |
| spaCy NER (B) | +0.078 (0.691→0.769) | +0.645 (0.014→0.659) | +0.129 | +0.013 | +0.050 |
| spaCy + gaz (D) | +0.084 (0.691→0.775) | +0.705 (0.014→0.719) | +0.138 | +0.017 | +0.050 |

Semantic detection is entirely responsible for the recall gain; the objective (A)
and ambiguous (C) classes are essentially unchanged across configs (below).

## 3. Per-entity-type (A/B/C/D class) mandatory recall

| Class | A core | C gazetteer | B spaCy | D spaCy+gaz |
|---|--:|--:|--:|--:|
| A objective (email/IP/SSN/token) | 0.812 | 0.812 | 0.817 | 0.817 |
| **B semantic (names/orgs)** | **0.014** | **0.340** | **0.659** | **0.719** |
| C ambiguous (numbers/dates/IDs) | 0.674 | 0.674 | 0.700 | 0.699 |

The entire movement is in class **B**. Objective PII was already strong; the
gazetteer 24×'s name recall model-free, and spaCy roughly doubles that again.

## 4. False-positive impact (the benign utility test)

Measured as the fraction of characters redacted in benign public prose that
**should not** be redacted (public figures, well-known orgs, dates, numbers):

| Config | benign FP rate | what it wrongly redacts |
|---|--:|---|
| A core | **0.000** | nothing |
| C gazetteer | **0.000** | nothing |
| B spaCy NER | 0.050 | `Moon`, `Microsoft`, `Washington`, `Redmond`, `Europe`, `Queensland`, `Australia`, `Boston`, `Mount Everest`, `Nepal`, `China`, `Earth` |
| D spaCy + gaz | 0.050 | the same public-figure over-redaction |

**This is the decisive finding.** spaCy NER redacts essentially every proper noun
in ordinary prose — a 5% character over-redaction rate on benign text, versus
**0%** for the gazetteer. On the RedactionBench corpus the same effect shows as
PChar collapsing from 0.75 (core) / 0.73 (gazetteer) to 0.54 (spaCy). The
gazetteer's precision-gated cues fire only on genuine name contexts.

## 5. Performance / memory overhead

| Config | throughput | slowdown | peak RSS | Δ RSS | startup | p95 latency | model size |
|---|--:|--:|--:|--:|--:|--:|--:|
| A core | 467K ch/s | 1× | 157 MB | — | 0.02 s | 98 ms | 0 |
| C gazetteer | 239K ch/s | 2.0× | 161 MB | +4 MB | 0.02 s | 186 ms | ~6 KB lists |
| B spaCy NER | 12K ch/s | **39×** | 364 MB | **+207 MB** | 2.0 s | **4027 ms** | ~12 MB model + spaCy |
| D spaCy + gaz | 12K ch/s | 39× | 377 MB | +220 MB | 2.0 s | 4266 ms | same |

The gazetteer is a pure-Python, dependency-free set of anchored regexes: **+4 MB,
2× slower, no startup cost, no model.** spaCy costs a 39× throughput hit, +200 MB
resident, a 2 s cold start, and multi-second per-document latency — a large price
for the constant-memory / high-throughput design. Streaming memory stays O(1) for
all configs (peak RSS is flat in document length; it does not grow with input).

## 6. Examples of newly recovered entities (gazetteer, on RedactionBench)

Names the deterministic core missed entirely, now recovered at the correct span:

- `Melissa Schettler` (form-field cue: `Name:`)
- `Laramie Carr` (honorific: `Dr.`)
- `Diane Luna` (gazetteer given name + surname)
- `Brændá` (cue; accented Latin name)
- `Keith Tanner` (cue: `Signature of Student:`)
- `Leona Qureshi` (professional suffix: `, MD`)

## 7. Examples of newly introduced false positives

- **Gazetteer**: none on the benign set (0.000). On RedactionBench the residual
  precision cost (PChar 0.753→0.731) is capitalized non-name phrases in headers
  and a few org-designator over-reaches; small and bounded.
- **spaCy NER**: substantial — every public place/org/person in benign prose
  (`Moon`, `Microsoft`, `Washington`, `Nepal`, `Earth`, …). This is the utility
  degradation a redaction system must weigh.

## 8. Is the stronger (spaCy) detector worth its cost?

**It depends on the deployment, and for most it is not the default choice.**

- **For utility-preserving redaction** (keep documents readable, redact only what
  is truly sensitive): **no.** spaCy's 5% benign over-redaction, 39× slowdown, and
  +200 MB are a poor trade for +0.05 mandatory recall over the gazetteer, and its
  F1 (0.539) is *below* the gazetteer's (0.547).
- **For maximum-recall PHI/PII redaction** (over-redaction acceptable, throughput
  not critical, e.g. a one-off clinical de-identification pass): **yes** — spaCy's
  mandatory recall (0.769–0.774) is the highest measured, and names are caught in
  free prose the gazetteer cannot reach.
- **The ideal** is a *precise* neural NER (e.g. a GLiNER PII model), which the
  leaderboard shows scoring 0.42–0.47 R-Score — higher recall than spaCy at better
  precision. That needs a model download (blocked here); the interface is ready
  (§ below).

## 9. Recommended architecture

A precision-ordered cascade, with the semantic tier chosen by deployment need:

1. **Deterministic** high-precision patterns + validators (objective PII/credentials).
2. **Label-anchored identifier cascade** (context-gated structured IDs).
3. **Gazetteer/context name detector** — *on by default* for names/orgs: best F1,
   zero benign FP, negligible cost, no dependency.
4. **Optional neural NER** (spaCy now; GLiNER/ONNX when a model is provided) — for
   deployments that need maximum name recall and accept the precision/throughput cost.
5. **Entropy** tier for undocumented secrets.
6. **Contextual scoring + overlap reconciliation** (higher-confidence, more-specific
   candidates win; a high-confidence semantic candidate is never dropped by a
   lower-confidence overlap — verified by test).
7. **Confidence-threshold filtering** (the `min_confidence` knob sweeps the whole
   cascade's precision/recall frontier — see the sweep below).
8. **Streaming redaction** — unchanged; all tiers run on bounded windows.

Default recommendation: **core + gazetteer** (best F1, zero benign FP, O(1) memory,
high throughput). Add neural NER only where the recall/precision/throughput trade
is justified.

### Threshold sweep (global `min_confidence`, gazetteer config)

| thr | PChar | RChar | F1 | Mandatory | benign FP |
|--:|--:|--:|--:|--:|--:|
| 0.50 | 0.731 | 0.437 | **0.547** | 0.720 | 0.000 |
| 0.60 | 0.73  | 0.427 | 0.535 | 0.705 | 0.000 |
| 0.72 | 0.871 | 0.289 | 0.434 | 0.450 | 0.000 |
| 0.85 | 0.918 | 0.275 | 0.423 | 0.430 | 0.000 |

The default 0.5 is the best-F1 operating point; raising the threshold filters the
whole cascade toward precision (up to PChar 0.92), for deployments that prefer it.

### Bring-your-own ONNX NER model (interface, no model bundled)

The `OnnxPiiDetector` tier (`detectors/onnx_ner.py`) is a complete local,
CPU-only, no-egress interface for a stronger model — verified by
`tests/test_onnx_ner.py` (decode/interface) without a model. To use one:

```bash
python -m benchmarks.redactionbench.run run --gazetteer \
    --onnx-model  path/to/model.onnx \
    --onnx-vocab  path/to/vocab.json \
    --onnx-labels path/to/id2label.json \
    --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/onnx
```

- **model.onnx** — a token-classification model emitting logits `(batch, seq,
  num_labels)`; inputs auto-detected (`input_ids`/`attention_mask`). CPU provider only.
- **vocab.json** — `{"token": id, …}` for the built-in `WordTokenizer` (word-level
  models); for a subword/transformer model, inject a Hugging Face tokenizer via the
  `tokenizer=` seam instead.
- **id2label.json** — `{"0": "O", "1": "B-PER", …}`; defaults to CoNLL IOB2.
- Tags map to PERSON/ORG/LOC; spans are decoded with per-span min-probability
  confidence and an adjustable `--onnx` `min_score`.

No model is downloaded or fabricated here (Hugging Face egress is blocked in this
environment); the loader is ready for a local GLiNER/DeBERTa/spaCy-ONNX export.

## 10. Core novelty for the research paper

The accuracy is *not* the novelty — frontier LLMs top RedactionBench at 0.714 and
this is a lightweight local system. The defensible novelty is the **architecture**:

1. **Constant-memory streaming redaction with provably boundary-loss-free output** —
   detection identical to whole-document processing, verified byte-for-byte across
   the corpus and 1,400+ adversarial boundary cases ([`VALIDATION.md`](VALIDATION.md)).
   This is the paper's central claim.
2. **A precision-ordered detector cascade** in which every tier declares its
   streaming context requirements, so semantic (NER) tiers plug in without breaking
   the O(1)-memory / equivalence guarantees.
3. **A model-free, precision-gated semantic tier** that recovers a large share of
   name recall at zero benign false positives and negligible cost — a defensible
   "strong baseline before you reach for a model", with a quantified
   precision/recall/utility/throughput trade-off vs. neural NER (this report).
4. **A rigorous evaluation methodology**: mandatory-vs-contextual separation, a
   benign false-positive set that exposes the over-redaction neural NER hides, and
   full instrumentation attributing every lost character to a pipeline stage.

Suggested paper experiments: the constant-memory scaling curve; throughput vs.
compiled scanners; the streaming-equivalence theorem + adversarial boundary
matrix; this A/B/C/D + benign-FP ablation; and a neural-NER comparison
(spaCy vs. GLiNER/ONNX) once a model is available.
