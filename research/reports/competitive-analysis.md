# Competitive Analysis

An honest read of where SafeStream-Redactor stands against the systems in
[`../comparisons/README.md`](../comparisons/README.md). The guiding rule: a credible,
qualified position beats an exaggerated "beats everything" claim. Only SafeStream's own
numbers here are measured; competitor characteristics are from public documentation.

## What SafeStream-Redactor does genuinely well

1. **Credential + high-entropy secret detection alongside PII, in one pass.** General PII
   engines (Presidio, Philter) and PII-focused ML models (Piiranha, GLiNER) target names,
   emails, and structured identifiers; they do not, by documentation, flag AWS/GitHub/
   Slack/Stripe keys or *undocumented* high-entropy secrets. Dedicated secret scanners do
   the latter but not PII. SafeStream covers both categories together.
2. **Constant-memory streaming over arbitrarily large input — measured.** Peak working
   memory is flat as input grows (see the memory table in the benchmark report); most PII
   libraries load the document into memory. This is the property that lets it redact a
   multi-GB log on a small machine.
3. **Local-first and free.** Runs fully offline with an egress guard and zero third-party
   runtime dependencies in the core. No data leaves the machine, no per-use billing. For
   regulated data that cannot go to a cloud API, this is decisive.
4. **Reproducible, self-contained deployment.** MIT license, PyPI wheel, Docker image,
   CLI, Python API, and an optional stdlib REST API — no cloud account required.
5. **Correctness guarantees for the streaming/parallel engine.** A formal model with
   proofs (streaming equivalence, parallel byte-identity, constant memory) mapped to the
   code that discharges each obligation — unusual for a tool in this space.

## Where SafeStream-Redactor is weaker (stated plainly)

- **Free-form PII recall without NER.** The regex-first core does not detect unstructured
  names/addresses. With the optional spaCy tier it does, but model-first systems
  (Presidio's NLP engine, Piiranha, GLiNER, cloud DLP) are stronger on nuanced,
  context-dependent PII out of the box. This is the honest cost of a regex-first design.
- **Breadth of entity types.** Cloud DLP services (Google, AWS) and Purview ship a much
  larger catalogue of built-in detectors (medical, financial, jurisdiction-specific) and
  keep them updated centrally.
- **Language coverage.** SafeStream's patterns and the default spaCy model are
  English-centric; cloud services and multilingual NER models cover many languages.
- **Governance/workflow features.** Purview and Tonic AI provide data cataloguing,
  policy management, lineage, and enterprise integration that SafeStream does not attempt.
- **Managed scale.** Cloud services scan petabyte-scale storage with no local compute;
  SafeStream runs on the machine you give it.

## Where each competitor class is the better choice

- **Presidio / Philter** — when you want a mature, extensible **PII** framework with a
  strong NLP pipeline and don't need credential/secret detection or constant-memory
  streaming. Philter is specifically strong for clinical (PHI) de-identification.
- **Piiranha / GLiNER** — when the task is model-based PII/entity extraction and you can
  afford a transformer model; they will out-recall regex on free-form text.
- **AWS Comprehend / Google DLP** — when data already lives in that cloud, you want
  breadth of built-in types with zero maintenance, and off-machine processing plus
  per-use cost are acceptable.
- **Microsoft Purview / Tonic AI** — when the need is enterprise **governance**, cataloguing,
  or synthetic-data/test-data workflows, not a single-purpose redaction pass.

## SafeStream-Redactor's defensible niche

> A **local-first, memory-bounded, hybrid (rule + entropy + optional ML) redactor that
> handles credentials/secrets *and* PII in one streaming pass over very large files, with
> reproducible packaging and formal correctness guarantees.**

It is the right tool when: the data cannot leave the machine; inputs are large (logs,
dumps, exports); you need both PII **and** secret/credential coverage; and you want a
free, auditable, self-contained pipeline. It is the wrong tool when you need managed
cloud scale, the widest possible built-in entity catalogue, multilingual coverage, or
enterprise data governance.

## Turning this into measured comparisons

The narrative above about competitors is *documentary*. To make specific comparisons
*measured*, the harness is ready:

```bash
# same corpus + ground truth, SafeStream vs a baseline, with CI and significance
python benchmarks/evaluate.py --jsonl corpus.jsonl \
    --system safestream --compare presidio --bootstrap 2000 --errors 10
```

Baselines wired through the common adapter today: `regex`, `presidio`, `scrubadub`,
`gitleaks`. Cloud/commercial systems need credentials, cost approval, and terms that
permit publishing benchmarks — until then they remain *documented*, not *measured*, and
are labelled as such throughout.
