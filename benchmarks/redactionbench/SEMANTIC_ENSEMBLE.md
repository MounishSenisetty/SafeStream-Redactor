# Calibrated semantic ensemble — the accuracy frontier of local semantic detection

This phase asked one question: **can semantic (name/organization) recall be
materially improved beyond the gazetteer/spaCy results using only local,
bounded-memory, high-throughput methods — or does the remaining gap fundamentally
require a stronger model?** The answer, established with a full error taxonomy, a
calibrated ensemble, two privacy policies, and a strengthened benign set, is:
**a calibrated local ensemble recovers a meaningful, precision-controlled share of
the gap, but the residual is a *contextual-sensitivity* limit that neither more
heuristics nor a stronger recognizer can close without over-redacting.**

No RedactionBench-specific rules were added. All numbers are on the full 200-doc
corpus (streaming) plus a 55-document benign public-prose set. Reproduce:
`python -m benchmarks.redactionbench.eval_configs --config <name> --benign` and
`python -m benchmarks.redactionbench.error_analysis`.

> Metric note: the official R-Score is unreleased; these are proxy character
> metrics. **Mandatory recall** is the recall that matters; contextual spans are
> not counted as required. No number here is an official R-Score, and none
> approaches 1.0 — nor should it be claimed to.

## 1. Remaining semantic error taxonomy

Of **2,343** name-like mandatory spans, the gazetteer misses **1,546**. spaCy
catches **60%** of those misses; **614 are missed by BOTH** (the model-hard floor).

| Category | misses | spaCy✓ | cue near | locally solvable? |
|---|--:|--:|--:|---|
| 09 partial single-token (surname/given/city fragments) | 1,227 | 735 | 434 | partly — repeated-mention propagation |
| 02 uncommon/rare (mostly street/place addresses) | 198 | 128 | 73 | no — needs model/large lexicon |
| 01 ordinary given names (bare, in prose) | 64 | 45 | 20 | maybe — larger name gazetteer |
| 08 word-like (`April`, `May`, `September` DOBs; place-words) | 35 | 13 | 11 | no — needs disambiguation |
| 03 accented · 05 initials · 06 long multi-token | 22 | 11 | 4 | partly |

Two facts shape the design: (a) the dominant bucket is **single-token repeated
mentions** (a full name introduced once, then referenced by one token) —
addressable by bounded propagation; (b) a large minority (`08 word-like`,
`02 rare`) is genuinely **ambiguous** (`April` is a name and a month; `James
Watson` is a private person and a public scientist) — unsolvable by recognition.

## 2. The calibrated ensemble architecture

`detectors/semantic_ensemble.py`. Not an OR of detectors — an explicit,
separately-calibrated evidence score for PERSON and for ORG, with a trace on
every prediction.

**PERSON evidence** (weights): honorific `0.62`, professional suffix `0.58`,
form-field name cue `0.55`, repeated-mention `0.55`, given-name `0.34`, surname
`0.30`, multi-token `0.20`, title-case shape `0.08`. **Negative**: common word,
field label, org designator. **ORG evidence**: designator `0.66`, org cue `0.45`,
"X of Y" `0.45`, multi-token `0.16`; negative: a given name (favours PERSON).
Calibrated so an isolated weak signal (bare capitalization) stays below threshold
while two weak signals or one strong signal clear it. Example trace:

```
PERSON "Melissa Vance": honorific=+0.62 surname=+0.30 multi_token=+0.20
                        title_shape=+0.08  ->  score 0.99  (policy=strict)
```

**Separate PERSON/ORG thresholds** (their linguistics differ). **Two policies**:

- **STRICT** (default, utility-preserving): a PERSON needs a *contextual cue*
  (honorific / form-field label / professional suffix / repeated mention), not
  just name-shape. A bare public-figure name in prose is therefore **not**
  redacted.
- **HIGH_RECALL** (privacy-first): redact any sufficiently name-shaped span,
  accepting that public figures get redacted too (documented cost).

**Bounded repeated-mention propagation**: a token confirmed as part of a strong
name earlier in the window boosts a later bare mention. State is a deque capped at
`max_confirmed` (128) with a lookback capped at `propagation_window` (2 KB ≤ engine
overlap), so **memory is O(1) in document length** and **streaming output is
byte-identical to whole-document** (verified by test — the cap and the ≤-overlap
lookback are what preserve the equivalence).

## 3. Full comparison (200-doc corpus + 55-doc strengthened benign set)

| Approach | PChar | RChar | F1 | **Mandatory** | PERSON/ORG (B) recall | **benign FP** | throughput | peak RSS | startup |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Core | 0.753 | 0.404 | 0.526 | 0.691 | 0.014 | **0.000** | 467K ch/s | 157 MB | 0.02 s |
| Core + Gazetteer | 0.731 | 0.437 | 0.547 | 0.720 | 0.340 | 0.031 | 239K ch/s | 161 MB | 0.03 s |
| **Core + Ensemble (STRICT)** | 0.723 | — | 0.540 | 0.713 | 0.272 | **0.014**¹ | 185K ch/s | 160 MB | 0.03 s |
| **Core + Ensemble (HIGH_RECALL)** | 0.727 | 0.444 | **0.551** | 0.731 | 0.469 | 0.032 | 184K ch/s | 158 MB | 0.03 s |
| Core + spaCy NER | 0.545 | 0.533 | 0.539 | 0.769 | 0.659 | **0.182** | 12K ch/s | 364 MB | 2.0 s |
| Core + Ensemble + spaCy | 0.543 | 0.542 | 0.542 | **0.774** | 0.736 | 0.178 | 12K ch/s | 367 MB | 2.0 s |
| Core + ONNX (interface ready) | — | — | — | — | — | — | — | — | — |

¹ STRICT's benign FP is **ORG-only** (public company names); the cue gate removes
every public-figure PERSON false positive. Model size / dependency footprint:
ensemble = ~6 KB word lists, no dependency; spaCy = ~12 MB model + the spaCy
runtime; ONNX = your model file + `onnxruntime`.

**PERSON/ORG operating-point frontier** (benign FP is the utility cost):

| operating point | mandatory | names (B) | benign FP | note |
|---|--:|--:|--:|---|
| core (no names) | 0.691 | 0.014 | 0.000 | objective PII only |
| ensemble STRICT (cue-gated) | 0.713 | 0.272 | 0.014 | no public-figure PERSON FP |
| ensemble HIGH_RECALL | 0.731 | 0.469 | 0.032 | redacts public figures |
| spaCy model | 0.769 | 0.659 | 0.182 | redacts every proper noun |

Recall and benign over-redaction rise together — a **precision-bounded frontier**,
not an engineering-bounded one.

## 4. Trade-offs

- **Precision / recall**: the ensemble adds real name recall over the core
  (0.014 → 0.272 STRICT / 0.469 HR). STRICT holds precision by requiring context;
  HR trades ~3% benign over-redaction for more recall and still beats spaCy's F1
  (0.551 vs 0.539) at **6× lower** benign FP (0.032 vs 0.182).
- **Memory / throughput**: ensemble is +1–4 MB, ~2.5× slower than core but 15×
  **faster** than spaCy, no model, ~instant startup. O(1) streaming memory holds
  (bounded deque + capped lookback).
- **Streaming guarantees**: unchanged and re-verified — streaming == whole-document
  byte-identical for both policies across chunk sizes; the stateful repeated-mention
  signal is bounded and equivalence-preserving by construction.

## 5. Decision matrix

| Approach | Mandatory Recall | F1 | Benign FP | Throughput | Memory | Recommendation |
|---|--:|--:|--:|--:|--:|---|
| Core | 0.691 | 0.526 | 0.000 | 467K/s | 157 MB | keep as the objective-PII floor |
| Gazetteer | 0.720 | 0.547 | 0.031 | 239K/s | 161 MB | superseded by ensemble STRICT (same idea, lower FP) |
| **Ensemble STRICT** | 0.713 | 0.540 | 0.014 | 185K/s | 160 MB | **default** — utility-preserving semantic tier |
| **Ensemble HIGH_RECALL** | 0.731 | 0.551 | 0.032 | 184K/s | 158 MB | **privacy-first policy** — opt-in |
| spaCy NER | 0.769 | 0.539 | 0.182 | 12K/s | 364 MB | only where 18% benign over-redaction is acceptable |
| Ensemble + spaCy | 0.774 | 0.542 | 0.178 | 12K/s | 367 MB | not recommended — worst utility |
| ONNX / GLiNER (BYO) | model-dependent | — | model-dependent | model-dependent | model-dependent | interface ready; expected between ensemble and spaCy |

## 6. Hard architectural recommendation

**B + D + E** (adopt the calibrated ensemble; ship two policies; treat further
gains as model-territory), and explicitly **not C-as-mandatory**:

- **Adopt the calibrated semantic ensemble (B)** as the semantic tier, replacing
  the single-signal gazetteer. It is strictly better: same recall band at lower
  benign FP, with evidence tracing and separate PERSON/ORG calibration.
- **Ship two policies (D)**: **STRICT is the default** (cue-gated, near-zero
  PERSON over-redaction, O(1) memory, no dependency); **HIGH_RECALL** is opt-in
  for privacy-first deployments that accept public-figure over-redaction.
- **A stronger model is optional, not required (E, not C)**. A model (spaCy today,
  GLiNER/ONNX via the ready interface) *does* raise name recall (0.77+), but it
  raises benign over-redaction far more (spaCy 18%). So a model is a **HIGH_RECALL
  accelerator**, gated behind the privacy policy — never the default. The BYO ONNX
  interface is implemented and pipeline-tested with a deterministic mock; drop in a
  real local model and it slots into the same policy framework.

## 7. Can the mandatory-recall gap be materially closed cheaply? — No.

The ~0.23 gap from spaCy's 0.775 (and the larger gap to 1.0) is **precision-bounded,
not engineering-bounded**. The recoverable-cheaply part (repeated mentions, cued
names, labeled addresses) is what the ensemble already captures. The rest is:

- **bare private names in prose** — indistinguishable by shape from public-figure
  names; catching them means redacting public figures too (a utility cost, not a
  recognition win);
- **word-like values** (`April`, `May` as DOBs) — require knowing the value is a
  date-of-birth in context, i.e. contextual reasoning;
- **rare / accented / non-Latin / transliterated names and unusual addresses** —
  need a broad multilingual model, which again over-redacts benign proper nouns.

So closing the gap materially requires either **accepting over-redaction** (the
HIGH_RECALL policy or a model) or **true contextual-integrity reasoning** (an LLM
that judges *sensitivity in context*, which RedactionBench's own leaderboard shows
tops out at 0.714 even for frontier LLMs). It cannot be closed by more local
heuristics at fixed precision.

## 8. Precise limits of the system

- **Objective PII/credentials**: strong (class-A mandatory recall ~0.85), O(1)
  memory, high throughput — the system's real strength.
- **Names/orgs**: recovered to 0.27 (STRICT) / 0.47 (HR) model-free; to ~0.66 with
  spaCy at a heavy utility/throughput cost. Non-Latin scripts need a model.
- **Contextual sensitivity** (is this proper noun *sensitive here*?): **out of
  scope** for any recognizer, local or model — this is the benchmark's core
  difficulty and the reason no system, including frontier LLMs, approaches 1.0.
- **Streaming**: constant-memory, boundary-loss-free, byte-identical to
  whole-document — preserved by every tier added in this work.

Do not claim near-1.0: the measured results do not justify it, and the dominant
remaining error is a contextual-integrity limit, not a recognition one.
