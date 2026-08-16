# Competitor Capability Comparison (rendered)

Source of truth: [`competitor-comparison.csv`](competitor-comparison.csv). Narrative and
caveats: [`../../comparisons/README.md`](../../comparisons/README.md).

**Evidence:** SafeStream = **Measured** (this repo). All competitors = **Documented**
(from public docs; not benchmarked here). Legend: ● yes · ○ no/limited · ▲ optional/add-on
· ? unknown (genuinely not documented — not a "no").

| Capability | SafeStream | Presidio | Philter | Piiranha | GLiNER | Grepture | Private AI | AWS Comprehend | Google DLP | MS Purview | Tonic AI |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Runs offline / local | ● | ● | ● | ● | ● | ● | ▲ | ○ | ○ | ○ | ▲ |
| Open source | ● | ● | ● | ● | ● | ● | ○ | ○ | ○ | ○ | ○ |
| PII detection | ● | ● | ● | ● | ● | ▲ | ● | ● | ● | ● | ● |
| Credential/secret detection | ● | ○ | ○ | ○ | ○ | ● | ? | ○ | ▲ | ▲ | ? |
| High-entropy secrets | ● | ○ | ○ | ○ | ○ | ● | ? | ○ | ○ | ○ | ? |
| Rule / regex | ● | ● | ● | ○ | ○ | ● | ● | ● | ● | ● | ● |
| ML / NER | ▲ | ● | ● | ● | ● | ○ | ● | ● | ● | ● | ● |
| Custom rules | ● | ● | ● | ○ | ▲ | ● | ● | ▲ | ● | ● | ● |
| Plugin/extension | ● | ● | ? | N/A | N/A | ? | ? | ○ | ○ | ▲ | ? |
| Streaming / large files | ● | ○ | ? | ○ | ○ | ● | ? | ○ | ● | ● | ● |
| Bounded/constant memory | ● (measured) | ○ | ? | ○ | ○ | ? | ? | N/A | N/A | N/A | ? |
| CLI | ● | ▲ | ● | ○ | ○ | ● | ▲ | ▲ | ▲ | ▲ | ▲ |
| REST API | ● | ● | ● | ○ | ○ | ○ | ● | ● | ● | ● | ● |
| Docker image | ● | ● | ● | ▲ | ▲ | ? | ● | N/A | N/A | N/A | ● |
| Python library | ● | ● | ▲ | ● | ● | ▲ | ● | ● | ● | ▲ | ● |
| Redaction/transform | ● | ● | ● | ○ | ○ | ○ | ● | ▲ | ● | ● | ● |
| Reversible pseudonym | ● | ▲ | ○ | ○ | ○ | ○ | ● | ○ | ● | ▲ | ● |
| No data leaves machine | ● | ● | ● | ● | ● | ● | ▲ | ○ | ○ | ○ | ▲ |
| Free | ● | ● | ● | ● | ● | ● | ○ | ○ | ○ | ○ | ○ |
