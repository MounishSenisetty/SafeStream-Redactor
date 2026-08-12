# ADR 0003 — Independent accuracy evaluation, and what it changed

- Status: accepted
- Date: 2026-08-12

## Problem

The project's own benchmark corpora are synthetic and self-generated: gold
positives are emitted in the exact canonical formats the detectors target, so a
near-perfect score measures format coverage and false-positive resistance, not
real-world recall. The README already says this. But "not a real recall number"
is not the same as *having* a real recall number. Without one, accuracy work is
blind and the synthetic score can hide real regressions.

## Decision

Measure detection quality against an **independent, externally-authored**
corpus, kept strictly separate from the synthetic regression fixture.

- Corpus: the Microsoft `presidio-research` synthetic dataset
  (`synth_dataset_v2.json`, 1500 records, template-generated from real name /
  address / locale lists). It was authored by another team for a different
  tool, so it is not tuned to SafeStream's formats — its phone numbers,
  addresses, and cards appear in the messy, non-canonical shapes real data has.
- Harness: `benchmarks/eval_dual.py` runs SafeStream over each record, matches
  predictions to gold spans by ≥50 % overlap and type, and reports per-type and
  micro P/R/F1 for the entity classes the deterministic core targets
  (`email`, `phone`, `credit_card`, `ssn`, `ip`). `PERSON`/`ORG`/`GPE` are out
  of scope for the regex core (they need the NER tier) and are not scored here.
- The corpus is fetched on demand (it is not vendored) and the evaluation is
  kept **separate** from the synthetic benchmark so the two can never be
  conflated.

## What it revealed

Baseline on the independent corpus (307 in-scope gold entities):

| type        | P     | R     | F1    |
| ----------- | ----- | ----- | ----- |
| email       | 1.000 | 1.000 | 1.000 |
| phone       | 1.000 | 0.446 | 0.617 |
| credit_card | 0.977 | 0.926 | 0.951 |
| ssn         | 1.000 | 1.000 | 1.000 |
| ip          | 1.000 | 1.000 | 1.000 |
| **micro**   | 0.988 | 0.801 | 0.885 |

The synthetic benchmark reported phone P/R = 1.0. The independent corpus showed
**phone recall of 0.446** — more than half of real phone numbers missed. The
gap was the design's precision tuning: bare numbers only fired with a nearby cue
word ("call", "tel"), which real forms and logs rarely provide, so common
formats (`905-674-3793`, extensions, international groupings) were dropped.

## What changed, and what deliberately did not

**Fixed (recall up, precision held):**

- A dedicated NANP pattern `NNN-NNN-NNNN` (dash or dot). This grouping is
  phone-specific — it cannot be an SSN (`NNN-NN-NNNN`), an ISO date, or an IPv4
  address — so it scores above threshold with no cue word.
- Extension support (`x4587`, `ext. 12`, `#99`) absorbed into the match, with
  the extension digits excluded from the 7–15 digit length check.

Result: phone recall **0.446 → 0.565**, precision still **1.000**, micro F1
**0.885 → 0.907**. The synthetic adversarial corpus stayed at P = R = 1.0, so
no false-positive regression.

**Measured and rejected:** promoting the bare, cue-less phone pattern to fire on
its own. On the independent corpus this lifted phone recall to 0.761 but dropped
phone precision to **0.769** (21 false positives) — real over-redaction of
dates, IDs, and zip+4 codes. Micro F1 was flat (0.907 → 0.908). Crucially, the
*synthetic* adversarial corpus reported **zero** precision cost for the same
change: it under-estimates real-world false positives, which is exactly why an
independent corpus is required. Bare cue-less phones stay context-gated.

**Examined and left alone:** the 10 missed credit cards are all 12-digit numbers
(below the 13–19 digit ISO card range); admitting them would add more Luhn-valid
false positives than true cards on real data. The 3 credit-card false positives
are 14-digit Luhn-valid non-cards that only context could disambiguate.

## Consequences

- There is now a real, reproducible accuracy number, honestly separated from the
  synthetic fixture, and a harness to catch accuracy regressions.
- The remaining phone recall gap (loosely-grouped international numbers with no
  separators or cue) is a genuine precision/recall trade-off that regex cannot
  close without over-redacting; closing it needs context/NER, tracked as future
  work. This is stated rather than papered over.
- The evaluation covers only the deterministic core's entity classes. Free-text
  `PERSON`/`ORG`/`LOC` recall (the NER tier) is not yet independently measured;
  that is the next evaluation to add.
