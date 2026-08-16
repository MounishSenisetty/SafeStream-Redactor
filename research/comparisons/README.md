# Comparison with Existing Systems

This is a **capability comparison built from public documentation**, not a head-to-head
benchmark. Read the labels carefully:

- **Only SafeStream-Redactor's accuracy/throughput/memory numbers in this repository are
  measured** (see [`../reports/benchmark-report.md`](../reports/benchmark-report.md)).
  Every competitor cell below reflects **documented** capability from the project's own
  docs/README, not a run we performed.
- A blank or `?` means **not documented / unknown** — it is *not* a "no". Turning unknown
  into "no" would be dishonest (Rule of this project: never turn "unknown" into "no").
- Systems are not equivalent. A local OSS library, a cloud API, and an enterprise
  governance platform solve different problems; the "better" system depends entirely on
  the use case.

Evidence status legend, used in the analysis and tables:

| Label | Meaning |
|---|---|
| **Measured** | We ran it in this repo and recorded raw results. |
| **Documented** | Stated by the vendor/project's public documentation. |
| **Not benchmarked** | Runnable in principle, but not executed in this environment. |
| **N/A** | The capability does not apply to that kind of system. |
| **?** | Not found in public documentation; unknown. |

## System classification

| System | Category | Deployment | License / cost |
|---|---|---|---|
| **SafeStream-Redactor** | Local OSS library + CLI + REST | Self-hosted, offline | MIT, free |
| Microsoft Presidio | Local OSS framework | Self-hosted | MIT, free |
| Philter | Local OSS (clinical de-id) | Self-hosted | Apache-2.0, free |
| Piiranha | OSS ML model (PII NER) | Self-hosted (model) | Open weights, free |
| GLiNER | OSS ML model (general NER) | Self-hosted (model) | Open weights, free |
| Grepture | OSS/utility (secret/PII grep-style) | Self-hosted | Open source |
| Private AI | Commercial | API + on-prem container | Paid |
| AWS Comprehend (PII) | Cloud API | Managed cloud | Paid, usage-based |
| Google Cloud Sensitive Data Protection (DLP) | Cloud API | Managed cloud | Paid, usage-based |
| Microsoft Purview | Enterprise governance platform | Cloud/M365 | Enterprise licensing |
| Tonic AI | Commercial data platform | SaaS + on-prem | Paid |

## Capability matrix (documented; SafeStream = measured where noted)

Legend: ● documented yes · ○ documented no/limited · ? unknown · ▲ optional/add-on

| Capability | SafeStream | Presidio | Philter | Piiranha | GLiNER | Grepture | Private AI | AWS Comprehend | Google DLP | MS Purview | Tonic AI |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Runs fully offline / local | ● | ● | ● | ● | ● | ● | ▲ (container) | ○ | ○ | ○ | ▲ |
| Open source | ● | ● | ● | ● | ● | ● | ○ | ○ | ○ | ○ | ○ |
| PII detection | ● | ● | ● | ● | ● | ▲ | ● | ● | ● | ● | ● |
| Credential/secret detection | ● | ○ | ○ | ○ | ○ | ● | ? | ○ | ▲ | ▲ | ? |
| High-entropy secret detection | ● | ○ | ○ | ○ | ○ | ● | ? | ○ | ○ | ○ | ? |
| Rule/regex detection | ● | ● | ● | ○ | ○ | ● | ● | ● | ● | ● | ● |
| ML / NER detection | ▲ (spaCy) | ● | ● | ● | ● | ○ | ● | ● | ● | ● | ● |
| Custom rules/patterns | ● | ● | ● | ○ | ▲ | ● | ● | ▲ | ● | ● | ● |
| Plugin/extension mechanism | ● | ● | ? | N/A | N/A | ? | ? | ○ | ○ | ▲ | ? |
| Streaming / large-file input | ● | ○ | ? | ○ | ○ | ● | ? | ○ (size limits) | ● (storage scan) | ● | ● |
| Bounded / constant memory | ● (measured) | ○ | ? | ○ | ○ | ? | ? | N/A | N/A | N/A | ? |
| CLI | ● | ▲ | ● | ○ | ○ | ● | ▲ | ▲ (SDK) | ▲ (SDK) | ▲ | ▲ |
| REST API | ● | ● | ● | ○ | ○ | ○ | ● | ● | ● | ● | ● |
| Docker image | ● | ● | ● | ▲ | ▲ | ? | ● | N/A | N/A | N/A | ● |
| Python library | ● | ● | ▲ | ● | ● | ▲ | ● | ● (boto3) | ● (client) | ▲ | ● |
| Redaction / transformation | ● | ● | ● | ○ | ○ | ○ | ● | ▲ | ● | ● | ● |
| Reversible pseudonymisation | ● (keyed) | ▲ | ○ | ○ | ○ | ○ | ● | ○ | ● (crypto) | ▲ | ● |
| No data leaves the machine | ● | ● | ● | ● | ● | ● | ▲ | ○ | ○ | ○ | ▲ |
| Free | ● | ● | ● | ● | ● | ● | ○ | ○ | ○ | ○ | ○ |

The same matrix in CSV form:
[`../results/tables/competitor-comparison.csv`](../results/tables/competitor-comparison.csv)
· rendered:
[`../results/tables/competitor-comparison.md`](../results/tables/competitor-comparison.md).

## Notes and honest caveats

- **`?` cells are genuine unknowns.** Grepture, Piiranha, GLiNER, and the commercial
  systems have capabilities we could not confirm from public docs at the granularity of
  this table; we deliberately left them `?` rather than guess.
- **ML/NER: SafeStream is `▲`, not `●`.** Its ML footprint is the optional spaCy NER tier
  plus the confidence calibrator — deliberately smaller than model-first systems (Piiranha,
  GLiNER, Presidio's NLP engine). SafeStream is regex/entropy-first by design; that is a
  *trade-off*, not strictly a win (see the analysis report).
- **Cloud systems win on managed scale and breadth.** AWS Comprehend, Google DLP, and
  Purview cover more entity types out of the box, integrate with cloud storage/governance,
  and require no local compute — at the cost of sending data off-machine and per-use
  billing. For a local-first, offline requirement they are simply not applicable.
- **To turn any competitor cell into "Measured":** the harness already supports it —
  `benchmarks/evaluate.py --system {presidio,scrubadub,gitleaks,regex}` runs baselines on
  the *same* corpus and ground truth, with bootstrap CIs and a paired-significance test.
  Cloud/commercial systems require credentials, cost approval, and terms that permit
  benchmarking, which is why they are marked *Not benchmarked* here.

See [`../reports/competitive-analysis.md`](../reports/competitive-analysis.md) for the
narrative: where SafeStream is genuinely better, where it is worse, and its defensible
niche.
