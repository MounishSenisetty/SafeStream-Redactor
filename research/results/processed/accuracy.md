# Accuracy & Throughput — Measured Results

Generated from [`../raw/accuracy_2026-08-16.json`](../raw/accuracy_2026-08-16.json).
Environment: CPython 3.11.15, Linux x86_64, Intel Xeon @ 2.10 GHz (4 cores), 16 GB RAM.
Package 0.2.0, commit `ad38aa4`. Matching: type-aware, ≥50% span overlap.

| Corpus | Size | Gold entities | Precision | Recall | F1 | FP | FN | Throughput |
|---|---|---|---|---|---|---|---|---|
| Clean / canonical (`generate_dataset.py`) | 10.5 MB | 60,253 | 1.000 | 1.000 | 1.000 | 0 | 0 | 3.50 MB/s |
| Adversarial (`generate_hard_dataset.py`) | 5.2 MB | 70,169 | 0.999 | 1.000 | 1.000 | 45 | 0 | 2.06 MB/s |

Types benchmarked: email, phone, credit_card, ssn, ipv4 (the set both SafeStream and
Presidio's pattern recognizers cover).

## How to read these honestly

- **The clean-corpus F1 = 1.000 is a regression fixture, not a real-world accuracy
  claim.** Its gold positives use the same canonical formats the detector targets, so
  recall there is close to circular. It is useful for catching regressions, not for
  answering "how accurate is it on real data?".
- **The adversarial precision (0.999, 45 FP / 70,169) is the informative number.** The
  corpus is dense with hard negatives engineered to fool a naive matcher; SafeStream's
  validators (Luhn, SSN area/group rules, `ipaddress` parsing) reject almost all of them.
- **For a defensible real-world accuracy number**, run `benchmarks/evaluate.py` against an
  *independent* labeled corpus (Presidio-research, CoNLL-2003, n2c2) — recall on free-form
  names/addresses will be far lower without the `--ner` tier, and that gap is the honest
  state of a regex-first detector.

## Reproduce

```bash
python benchmarks/generate_dataset.py --size-mb 10
python benchmarks/run_benchmark.py

python benchmarks/generate_hard_dataset.py --size-mb 5 --out benchmarks/data_hard
python benchmarks/run_benchmark.py --data benchmarks/data_hard
```
