# RedactionBench deep audit — why the scores are what they are, what changed, and the real ceiling

This document answers the end-to-end audit request: verify the benchmark is not
manufacturing false failures, trace every real failure to a component, fix what
is genuinely fixable in a generalizable way (no benchmark hacks), and state
honestly what a defensible score is. All numbers are measured on the full
`RedactionBench/RedactionBench` corpus (revision `d45e9cec…`, 200 docs, 11
domains), streaming engine.

## 0. First: the harness is correct — the low score is not a measurement artifact

Before trusting any number, the harness itself was audited. Findings:

- **Offsets are character offsets, and correct.** `raw_text[94:101] == 'Melissa'`;
  spot-checks on documents containing non-ASCII (`Café`, `Brændá`) still align
  exactly. No byte/UTF-16 vs. character-offset bug (the classic source of false
  failures) exists.
- **Gold spans never overlap within a document** (0/200), so splitting the score
  by necessity (mandatory vs contextual) cannot double-count.
- **The character metric is independently reproducible.** Recomputing the
  redaction masks by hand for a document yields exactly the harness's tp/fp/fn.
- **Streaming = whole-document, byte-for-byte.** Predictions from the
  constant-memory chunked engine (even at 12-char chunks) are identical to
  whole-document detection across all 200 docs. **Chunk boundaries, overlap, and
  carry-over context are NOT causing missed entities.** This eliminates an entire
  class of suspected causes up front.
- **Matching is not exact-string.** Character coverage (the dataset's R-Score
  methodology) and ≥50%-overlap span matching are both used; partial spans and
  formatting differences are credited.

Conclusion: the score is low because of **what the system detects**, not because
the benchmark is scoring it unfairly.

## 1. Root causes of the low score, ranked by impact

RedactionBench labels every gold span by **necessity** — `mandatory` (16,993
spans) or `contextual` (36,293) — **not by PII type**. It is a contextual-integrity
*binary redaction* task, and its metric (R-Score) is character-level. Two facts
dominate everything below:

| # | Root cause | Evidence | Share of the gap | Fixable in this architecture? |
|---|---|---|---|---|
| 1 | **The `contextual` class is subjective and ultra-fine-grained.** 57% of all gold *characters*; median span length **1 character**; 20,598 of 36,293 spans are single characters — individual date digits, `/` separators, even the space inside a name. The paper reports **~47.7% human inter-annotator agreement** on contextual redactions. | span-length histogram; necessity split | ~57% of gold chars; the majority of "missed recall" | **No — and shouldn't be.** A DLP tool that blanket-redacts single spaces, date digits and separators destroys precision and document utility. This is the ceiling, not a bug. |
| 2 | **Names dominate the recoverable (mandatory) misses.** 45.5% of missed mandatory characters are person names (`Melissa`, `Schettler`, `Brændá`). Only **14%** of missed names have a label cue nearby; 86% are in prose/signatures. | mandatory-miss taxonomy; name-cue analysis | 45.5% of mandatory FN | **Only via NER.** Names have no regex signature. The optional spaCy tier lifts mandatory recall 0.686→0.765; higher needs a transformer-grade model that conflicts with the constant-memory/high-throughput/local-first design. |
| 3 | **Label-anchored identifiers were skipped.** Bare student/employee/account/national-id numbers and DOBs (`202184673`, `102294080031`, `03/08/1996`) — the deterministic tier skips them to protect precision. | mandatory-miss taxonomy: ssn-like 8.7% + numeric IDs within date/number 11.4% + part of alnum-id 17.6% | ~15–20% of mandatory FN | **Yes — fixed** (see §2). Recoverable precisely because the text names them. |
| 4 | **Compound / symbol-containing secrets slip the entropy tier.** e.g. `devPass_pP0p18yO3n!vT8wZ` splits on `!` into sub-tokens below the length/entropy floor. | direct entropy probes | small slice of alnum/other-text misses | Partially (a precision-sensitive lever; deliberately not force-tuned on this PII-centric corpus). |
| 5 | **Precision is dragged by the entropy tier over-firing.** 83% of all over-redaction (char FP) is `secret` (42,135 chars) — long high-entropy strings in `code`/`terminal`/`logs` docs that RedactionBench does not annotate as sensitive. | FP-by-type analysis | ~83% of char FP | This is largely a **benchmark domain mismatch** (RB doesn't comprehensively label secrets), not a defect — see §7. |

## 2. Core architectural changes made, and why they address the causes

Only change #3 is cleanly fixable without either overfitting the benchmark or
abandoning the architecture — so that is what was built, as a genuine, reusable
DLP capability rather than a benchmark patch.

**New tier: `LabeledIdentifierDetector` (`detectors/labeled_id.py`) — a
high-precision contextual cascade.** A cue word immediately to the left of an
otherwise-ambiguous value promotes it to a redaction, and only then:
`Student ID: 202184673`, `Account Number 102294080031`, `DOB 03/08/1996`,
`Patient MRN: A1234567`. Design properties:

- **Precision-safe by construction**: a match requires an explicit label cue; the
  cue vocabulary is the standard DLP set (identity / financial / health /
  government identifiers), deliberately *not* reverse-engineered from
  RedactionBench. Weak business-object cues (order/invoice/ticket) were dropped
  after they over-fired on non-personal numbers.
- **Only the value is emitted, never the label** — the redaction covers the
  sensitive characters and nothing more (no precision loss on the label word).
- **Type-honest**: SSN-shaped values are emitted as the generic `ID_NUMBER`, so a
  *valid* SSN keeps its validated `SSN` type (deterministic tier wins overlap
  resolution) while a labeled placeholder is still redacted.
- **Streaming-correct**: stateless and window-pure, with declared
  `StreamingRequirements` (cue→value window). Verified to produce byte-identical
  output streaming vs whole-document on the full corpus, preserving the O(1)
  memory and parallel-equivalence guarantees.

Causes #1 and #2 were deliberately **not** "fixed": chasing contextual single-char
spans (cause #1) is benchmark-gaming that destroys utility, and names (cause #2)
are an NER-model-quality problem already handled by the optional tier. Cause #5
(entropy over-firing) was deliberately **not** tuned down, because doing so to
please a corpus that under-labels secrets would overfit in the opposite
direction and weaken SafeStream's actual differentiator (see §7).

## 3. Modified files and key code paths

- `src/safestream_redactor/detectors/labeled_id.py` — **new** tier (cue→value
  rules, value-only emission, streaming requirements).
- `src/safestream_redactor/entities.py` — new `EntityType.DOB`, `EntityType.ID_NUMBER`.
- `src/safestream_redactor/severity.py` — severities for the two new types.
- `src/safestream_redactor/redactor.py` — wires the tier into the default cascade
  (on whenever SSN/PHONE/CREDIT_CARD/DOB/ID_NUMBER are in scope).
- `tests/test_labeled_id.py` — **new** regression suite (17 cases): label
  promotion, value-only spans, precision guards, invalid-SSN typing, casing,
  adjacency/repetition, Unicode, malformed input, streaming/chunk equivalence.
- Benchmark harness (`benchmarks/redactionbench/`) unchanged in behaviour; results
  regenerated.

Core streaming/detection contracts (`engine.py`, overlap sizing, parallel seam
check) are untouched — the new tier plugs into the existing detector protocol.

## 4. Benchmark results — before vs after (full 200 docs, streaming)

Character-level (R-Score methodology). "Before" = shipped pipeline; "After" =
with the label-anchored cascade.

| Config | Char P | Char R | Char F1 | Acc | Mandatory recall | Contextual recall |
|---|--:|--:|--:|--:|--:|--:|
| Core, **before** | 0.753 | 0.401 | 0.524 | 0.895 | 0.686 | 0.185 |
| Core, **after** (cascade) | 0.752 | 0.404 | 0.526 | 0.895 | 0.691 | 0.186 |
| Core + NER, **before** | 0.544 | 0.531 | 0.538 | 0.869 | 0.765 | 0.354 |
| Core + NER, **after** (cascade) | 0.545 | 0.533 | 0.539 | 0.869 | 0.769 | 0.355 |

The cascade adds precision-neutral recall (mandatory 0.686→0.691, precision held
at 0.752) — a small aggregate move **because names, not labeled IDs, dominate the
misses**. The cascade's value is real and generalizable (182 `id_number` + 24
`dob` detections on this corpus, and it helps any labeled-form data), but it
cannot move a score whose remaining error is 45% names + a subjective contextual
majority. Span-level type-agnostic numbers are reported in `report.md`; they are
secondary because RB over-segments each value into many single-char spans.

## 5. Remaining failure cases (with examples)

- **Names in prose/signatures** (86% of missed names) — `…Sincerely, Melissa
  Schettler`, `Dr. Laramie`. Require NER; the regex/entropy core cannot see them.
- **Contextual fragments** — single spaces inside names, individual date digits
  and `/` separators, isolated ZIP/year numbers. Not redacted by design;
  redacting them would gut precision and utility.
- **Semantic usernames / opaque codes** — `elenar_77`, `WVHS-Burn-77`,
  `pgSuper_devOnly_47Kx`: no format, no cue, not high-entropy enough. Genuinely
  ambiguous.
- **Symbol-containing passwords** — `devPass_pP0p18yO3n!vT8wZ`: a known
  entropy-tier limitation (splits on punctuation); a precision-sensitive lever
  left untouched here.
- **Unlabeled bare identifiers** — a 9-digit number with no cue is indistinguishable
  from any other 9-digit number; catching it would require redacting all numbers.

## 6. Performance / memory impact

- **Memory**: unchanged — O(1) streaming preserved. The new tier is window-pure
  and stateless; it declares a small cue→value overlap requirement (well under the
  8 KB default), so the engine's constant-memory bound is unaffected.
- **Throughput**: the tier is a handful of anchored regexes per window; the full
  200-doc streaming run completes in ~14 s (core), unchanged within noise from the
  baseline. No new runtime dependency.
- **Streaming correctness**: byte-identical streaming-vs-whole output verified on
  the whole corpus after the change.

## 7. Why a near-1.0 RedactionBench score would be misleading

This is the most important finding. A near-1.0 here is **not defensible for any
precision-respecting streaming redactor**, and pursuing it would mean gaming:

1. **Contextual redactions have ~47.7% human agreement** (paper). With a single
   gold annotation, exceeding human agreement means overfitting the annotators'
   idiosyncratic choices, not "being correct." 57% of gold characters live in
   this class.
2. **The contextual class rewards utility-destroying behavior** — redacting single
   spaces, individual date digits and separators. A tool that does this to score
   well is worse in the real world, which is exactly the outcome the request
   forbids.
3. **RedactionBench is built for LLM-scale contextual reasoning** — the paper
   benchmarks 35 LLMs and finds frontier LLMs beat the average human. It is
   out-of-domain for a deterministic O(1)-memory streaming engine by construction.
4. **The benchmark under-labels secrets/credentials** — SafeStream's actual
   differentiator. 83% of its "false positives" here are high-entropy strings RB
   simply did not annotate. Tuning that tier down to raise RB precision would
   weaken the tool on the task it is genuinely best at.

**A defensible way to read the result**: on the objective, high-agreement portion
— *mandatory* redactions — SafeStream covers **68.6%** of characters out of the
box and **76.5%** with NER, at 0.75 character precision, streaming in constant
memory. The path to higher *mandatory* recall is better NER for names, not more
regex. The overall all-gold F1 is bounded well below 1.0 by the subjective
contextual majority, and should be reported with the mandatory/contextual split,
never as a single headline number.

## Reproduce

```bash
pip install -e '.[redactionbench]'
# before/after are the same command; the cascade is on by default now
python -m benchmarks.redactionbench.run run \
    --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench
# NER config:
pip install -e '.[ner]' && python -m spacy download en_core_web_sm
python -m benchmarks.redactionbench.run run --ner \
    --data-dir benchmarks/data/redactionbench --out-dir benchmarks/results/redactionbench-ner
```
