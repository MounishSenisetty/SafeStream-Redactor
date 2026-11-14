# Real-world evaluation pipeline

Scores SafeStream and the baselines on an **authorised** corpus of real artefacts
(CI logs, application logs, configuration dumps, exports), double-annotated and
adjudicated. The corpus itself never enters the repository; only aggregate
results, document identifiers and character offsets do.

## Before collecting anything

A concrete plan for building such a corpus from public CI logs (sampling, consent,
annotation, analysis and the decisions it needs) is in `COLLECTION_PLAN.md`.


- **Authorisation.** Use only artefacts you are allowed to process for research:
  public CI logs or issue attachments from repositories whose licences permit it,
  or data from an organisation that authorises the study in writing.
- **Ethics review** where your institution requires it.
- **Live secrets.** Never test a discovered credential against a live service
  (the harness runs TruffleHog with `--no-verification`). Report live secrets to
  their owners through responsible disclosure, and record how in
  `provenance.json`.
- **Storage.** Keep the corpus encrypted at rest, with access limited to the
  annotators. Use opaque document identifiers (`ci-0001`), not file names or
  repository paths.
- **Publication.** Publish annotations, hashes and aggregate results only, never
  secret values or document text.

## Layout

The corpus lives in `$SAFESTREAM_REALWORLD_DIR` (default
`benchmarks/data/external/realworld/`, which is git-ignored):

```
provenance.json            required; see below
documents.jsonl            {"doc_id", "text", "source", "kind"} per line
annotations/<name>.jsonl   one file per annotator (two or more)
adjudicated.jsonl          gold after adjudication
```

- `source` is the system or repository a document came from. It is the cluster
  unit of the bootstrap, so documents from one source are resampled together.
- `kind` is free text (`ci-log`, `app-log`, `config`, ...), for reporting.
- An annotation line is `{"doc_id": ..., "spans": [{"start": 10, "end": 30,
  "type": "SECRET", "subtype": "aws_key", "necessity": "mandatory"}]}` with
  0-based, end-exclusive character offsets into `text`. `subtype` is optional.
  `necessity` defaults to `mandatory`. Every document must have a line in every
  file; use `"spans": []` for "nothing sensitive".
- Types: `SECRET`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`,
  `IP_ADDRESS`, `PERSON`, `LOCATION`, `ORGANIZATION`, `ID`, `USERNAME`, `URL`,
  `DATE_TIME`, `IBAN_CODE`, `CRYPTO`, `MAC_ADDRESS`, `OTHER`. See
  `ANNOTATION_GUIDELINES.md`.

`provenance.json` needs a non-empty string for each of `description`,
`authorisation`, `licence_or_agreement`, `ethics_review` (or why none was needed),
`collected` (date) and `live_secret_handling`. Validation fails without it.

## Procedure

Every command below runs from the repository root.

1. **Annotate** independently with two annotators, following
   `ANNOTATION_GUIDELINES.md`. If you used Label Studio, convert its JSON export
   (`--label-map` maps your label names to `TYPE` or `TYPE:subtype`):

   ```bash
   python -m benchmarks.realworld import-labelstudio export.json --label-map labels.json
   ```

2. **Validate** the layout, offsets, types, coverage and provenance. It prints
   counts only and exits non-zero on any issue:

   ```bash
   python -m benchmarks.realworld validate
   ```

3. **Measure agreement** before adjudicating: character-level Cohen's kappa
   (binary and typed), and span F1 (exact and overlap), with document-level and
   source-clustered intervals:

   ```bash
   python -m benchmarks.realworld agreement
   ```

4. **Adjudicate** the disagreements into `adjudicated.jsonl`, then validate
   again.

5. **Freeze** the corpus. This writes the test-only split manifest (document
   identifiers and the SHA-256 of the source, no text). Commit it. Loading the
   corpus afterwards fails if the data changes.

   ```bash
   python -m benchmarks.corpora.split realworld
   ```

6. **Run the systems** at a frozen, clean commit. Use the same commands and
   virtual environments as the other test splits:

   ```bash
   python -m benchmarks.harness --corpus realworld --split test --systems safestream-native safestream-native-spacy gitleaks trufflehog presidio-regex presidio-sm presidio-lg --venv-root VENVS --checkpoint-dir CKPT
   ```

7. **Score.** This writes the results JSON and, with `--latex-dir`, the three
   tables for the manuscript:

   ```bash
   python -m benchmarks.realworld score --system safestream=CKPT/realworld_test_safestream-native.json --system gitleaks=CKPT/realworld_test_gitleaks.json --pair safestream:gitleaks --name safestream=SafeStream --name gitleaks=gitleaks --latex-dir paper/journal/content/generated
   ```

## Outputs

- `research/results/raw/<date>_realworld_agreement.json`: pairwise agreement,
  overall and per type.
- `research/results/raw/<date>_realworld_scores.json`:
  - the harness metrics per system, with intervals at the document, cluster and
    two-stage (by source) levels, and paired differences on one resample matrix;
  - per-type and per-subtype coverage;
  - leaked mandatory spans per type, with document identifiers.

  `_credential_leaks` counts leaked spans of the types in `--credential-types`
  (default `SECRET`), for zero-tolerance acceptance criteria.
- `tab_realworld_{main,types,pairs}.tex`: tables that use the `\pc` and `\ns`
  macros of `paper/journal/content/preamble.tex`.

The harness checkpoints hold character offsets and types only. The real-world
corpus has no development split, so the harness's `--errors` option, which
writes document text, cannot be used on it.
