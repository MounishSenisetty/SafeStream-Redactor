# Research: Datasets, Benchmarks, Results, Comparisons

This directory holds **measured** results and the **documented** competitor comparison for
SafeStream-Redactor, plus everything needed to reproduce them. It follows the project's
non-negotiable rules: every number here comes from an actual run recorded with its
environment, and nothing is fabricated. Where a comparison is documentary rather than
measured, it is labelled as such.

## Layout

```
research/
├── README.md                     ← this file
├── comparisons/
│   └── README.md                 ← capability matrix vs 10 systems (documented)
├── reports/
│   ├── benchmark-report.md       ← measured SafeStream results, full detail
│   └── competitive-analysis.md   ← where SafeStream wins/loses, and its niche
└── results/
    ├── raw/                       ← JSON with metrics + full environment metadata
    │   ├── accuracy_2026-08-16.json
    │   └── memory_2026-08-16.json
    ├── processed/                 ← human-readable tables from the raw JSON
    │   ├── accuracy.md
    │   └── memory.md
    └── tables/
        ├── competitor-comparison.csv
        └── competitor-comparison.md
```

## What is measured vs documented

| Item | Status |
|---|---|
| SafeStream accuracy on clean + adversarial synthetic corpora | **Measured** |
| SafeStream throughput (MB/s) | **Measured** |
| SafeStream constant-memory (peak vs size) | **Measured** |
| Presidio / cloud / commercial systems | **Documented** (not benchmarked in this environment) |

Presidio *can* be measured here — `benchmarks/run_benchmark.py` runs it automatically when
`pip install 'safestream-redactor[bench]'` is present, and `benchmarks/evaluate.py
--system presidio` scores it on the same corpus. It was not installed in the environment
that produced these results, so it is reported as documented, not measured.

## Reproduce everything

```bash
pip install -e '.[dev]'

# 1. Accuracy + throughput (clean, then adversarial)
python benchmarks/generate_dataset.py --size-mb 10
python benchmarks/run_benchmark.py
python benchmarks/generate_hard_dataset.py --size-mb 5 --out benchmarks/data_hard
python benchmarks/run_benchmark.py --data benchmarks/data_hard

# 2. Constant-memory proof (peak memory vs file size — flat line == constant memory)
python benchmarks/scale_memory.py --sizes 8 32 64

# 3. Parallel byte-identity + speedup (optional; asserts identical output)
python benchmarks/parallel_speedup.py --size 64 --workers 1 2 4

# 4. Real accuracy on an INDEPENDENT corpus (the defensible number)
python benchmarks/evaluate.py --jsonl your_corpus.jsonl \
    --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn --ner \
    --system safestream --compare presidio --bootstrap 2000 --errors 10
```

Results in `results/raw/` record the git commit, package version, Python/OS/CPU/RAM, the
dataset and its size, the configuration, and the metrics — the metadata a reviewer needs
to trust and re-run them.

## Honest limitations of these results

- The synthetic corpora exercise **structured PII** (email/phone/card/SSN/IPv4). They do
  not measure free-form name/address recall — use `evaluate.py` with `--ner` on an
  independent corpus for that.
- Throughput is environment-specific (measured on a throttled 2.1 GHz shared vCPU); treat
  the MB/s figures as relative, not absolute hardware limits.
- The memory benchmark uses `tracemalloc`, which adds large timing overhead — its MB/s
  column is **not** a throughput measure; read the peak-MB column for the memory claim and
  the accuracy report for throughput.
- Competitor rows are documentary. See `comparisons/README.md` for the evidence labels.
