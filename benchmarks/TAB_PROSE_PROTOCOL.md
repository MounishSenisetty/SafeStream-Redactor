# Free-text configuration: development and confirmation protocol

Fixed and committed before any system was run on TAB's development or training
split. Nothing below is changed after the confirmation run.

## Why

On TAB's test split (127 ECHR judgments, scored once under the protocol of
`benchmarks/tab_score.py`), SafeStream's named-entity configuration had lower
character F1 than Presidio with the same spaCy model (0.380 against 0.592),
chiefly because it left dates unredacted, and no system protected direct
identifiers. Those test results are now **exposed**: they motivated this work,
so the TAB test split can no longer serve as held-out evidence for anything
designed here.

## Data

| Role | Data | Rule |
|---|---|---|
| Development | TAB development split (`tab_dev`, 127 judgments) | the only TAB data used to choose or tune anything |
| Confirmation (held out) | TAB training split (`tab_train`, 1,014 judgments) | never inspected or scored before the configuration is frozen; scored once |
| Secondary, exposed | TAB test split (`tab`) | reported, labelled exposed |

All three splits are disjoint (checked by document id). Manifests with source
SHA-256 are in `benchmarks/corpora/splits/`.

## What may be developed

A free-text configuration of SafeStream built from general mechanisms, not from
TAB-specific strings: which spaCy entity labels the named-entity tier redacts,
whether the opt-in date tier is on, a document-level consistency pass (redact
every occurrence of a value the pipeline detected elsewhere in the same
document), and label-anchored identifier cues. Every mechanism must keep the
streaming guarantee: it declares bounded span and context, or it is applied in
a second streamed pass whose added detector does.

## Freeze

The configuration is frozen by a commit that names it (a `Redactor` profile or
arguments) before the confirmation run. The confirmation run uses that commit.

## Confirmation run

Systems on `tab_train`: the frozen free-text configuration; SafeStream +spaCy as
evaluated in the paper; Presidio regex, sm and lg.

Metrics: as in `benchmarks/tab_score.py` (per-annotator gold: DIRECT and QUASI
mentions; character precision, recall and F1; entity recall on direct and on
quasi identifiers; direct-protected rate), 95% paired document bootstrap,
2,000 resamples, seed 0.

Planned comparisons (free-text configuration minus each): Presidio sm and
Presidio lg, on character F1, character recall, direct entity recall and quasi
entity recall. Everything else is descriptive.

The streamed output of the frozen configuration is compared with its
whole-document output on `tab_train` under random chunkings.

Results are reported whatever their direction.
