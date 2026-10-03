# SafeStream-Redactor — Benchmark Report

> **Not reproduced (2026-10-03).** The figures below come from an earlier harness and
> environment and were not reproduced by the Phase 0 baseline (`benchmarks/harness.py`,
> isolated per-tool virtualenvs, one thread per tool, dev splits). Treat them as
> historical. Current measured numbers: the README's Evaluation section and
> [`research/reports/gap-report.md`](gap-report.md).

**Measured** results for SafeStream-Redactor, with the environment and commands needed to
reproduce them. This report quotes only numbers we actually produced; competitor
characteristics live in [`competitive-analysis.md`](competitive-analysis.md) and are
labelled *documented*, not measured.

## Environment

| | |
|---|---|
| Package version | 0.2.0 |
| Git commit | `ad38aa457e3e2cebce5e3536d9d8cbdffad31930` (branch `feature/rest-api-and-architecture-diagrams`) |
| Python | CPython 3.11.15 |
| OS | Linux 6.18.5-fc-v20, x86_64 |
| CPU | Intel Xeon @ 2.10 GHz, 4 cores (shared/throttled vCPU) |
| RAM | 16 GB |
| Date | 2026-08-16 |

> Throughput is environment-specific and this vCPU is throttled; treat MB/s figures as
> **relative**, not a hardware ceiling.

## 1. Accuracy & throughput

Matching is type-aware with ≥50% span overlap. Types: email, phone, credit_card, ssn,
ipv4. Full data: [`../results/processed/accuracy.md`](../results/processed/accuracy.md),
raw: [`../results/raw/accuracy_2026-08-16.json`](../results/raw/accuracy_2026-08-16.json).

| Corpus | Size | Gold | Precision | Recall | F1 | FP | FN | Throughput |
|---|---|---|---|---|---|---|---|---|
| Clean / canonical | 10.5 MB | 60,253 | 1.000 | 1.000 | 1.000 | 0 | 0 | 3.50 MB/s |
| Adversarial | 5.2 MB | 70,169 | 0.999 | 1.000 | 1.000 | 45 | 0 | 2.06 MB/s |

**What these mean (read before quoting):**

- The **clean** F1 = 1.000 is a *regression fixture*, not a real-world accuracy claim: its
  gold positives use the canonical formats the detector targets, so recall there is
  near-circular.
- The **adversarial precision** (0.999; 45 FP across 70,169 gold) is the genuinely
  informative number — the corpus is dense with hard negatives (Luhn-failing 16-digit
  numbers, 5-octet IPs, invalid-area SSNs, UUIDs, git hashes) designed to fool a naive
  matcher. SafeStream's validators reject almost all of them.
- **Free-form PII recall is not measured here.** These corpora are structured PII only.
  For a defensible real-world number, run `benchmarks/evaluate.py` against an independent
  labeled corpus with `--ner`; recall on names/addresses will be substantially lower
  without NER — the honest state of a regex-first detector.

## 2. Constant memory (Theorem 3)

Full data: [`../results/processed/memory.md`](../results/processed/memory.md), raw:
[`../results/raw/memory_2026-08-16.json`](../results/raw/memory_2026-08-16.json).

| Input size | Peak memory |
|---|---|
| 8 MB | 2.75 MB |
| 32 MB | 2.75 MB |

Peak allocation is **identical** as input grows 4× — memory is independent of input size.
Corroborated at 1 GB by `tests/test_memory.py` (asserts peak < 16 MB;
`pytest -m memory -o addopts=''`).

## 3. Parallel byte-identity (Theorem 2)

Not re-run in this environment, but the property is enforced continuously:
`benchmarks/parallel_speedup.py` and `tests/test_parallel.py` assert that
`redact_file(..., workers=N)` output is **byte-identical** to the sequential pass at every
worker count, or falls back to sequential (the seam valve). The README documents ~3.7×
on 4 cores from a prior run.

```bash
python benchmarks/parallel_speedup.py --size 64 --workers 1 2 4   # asserts byte-identity
```

## 4. Comparison with existing tools

- **A like-for-like Presidio head-to-head is now measured** (2026-10-02, one run):
  [`benchmarks/PRESIDIO_COMPARISON.md`](../../benchmarks/PRESIDIO_COMPARISON.md),
  raw data in `results/raw/presidio_compare_2026-10-02.json`. Pattern tier (SafeStream
  rules vs Presidio's pattern recognizers, no NLP engine): 15–147× faster. NER tier
  (both on `en_core_web_sm`): ~2× faster, with SafeStream using more memory. The earlier
  "P=0.649" figure differs from this run (0.741); that run's configuration is not recorded in
  the repo, so this one supersedes it.
- A **documented** capability comparison against 10 systems (Presidio, Philter, Piiranha,
  GLiNER, Grepture, Private AI, AWS Comprehend, Google DLP, Microsoft Purview, Tonic AI) is
  in [`../comparisons/README.md`](../comparisons/README.md); the analysis of where
  SafeStream wins, loses, and fits is in
  [`competitive-analysis.md`](competitive-analysis.md).
- To turn a competitor into *measured*: `benchmarks/evaluate.py --system presidio`
  (also `regex`, `scrubadub`, `gitleaks`) scores it on the **same** corpus and ground
  truth, with bootstrap CIs and a paired-significance test.

## 5. Summary

On this environment, SafeStream-Redactor: holds **P=0.999 under adversarial distractors**
with zero missed structured-PII entities; shows **flat peak memory** as input scales (2.75
MB at both 8 and 32 MB, <16 MB at 1 GB); and guarantees **byte-identical parallel output**.
Its measured weakness is raw throughput (2–3.5 MB/s single-core, throttled) — a known
trade-off against constant memory and credential coverage, partly addressed by
`--workers`. Free-form PII recall and cloud/commercial comparisons remain to be measured
against independent corpora with the harness already provided.
