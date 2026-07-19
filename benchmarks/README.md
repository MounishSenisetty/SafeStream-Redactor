# Benchmarks

Compares SafeStream-Redactor against [Microsoft Presidio](https://github.com/microsoft/presidio)
on a synthetic, labeled dataset: precision / recall / F1 (type-aware, ≥50% span overlap)
and raw throughput in MB/s.

```bash
# 1. generate a labeled corpus (default 10 MB -> benchmarks/data/)
python benchmarks/generate_dataset.py --size-mb 10

# 2. run
python benchmarks/run_benchmark.py

# optional: include Presidio in the comparison
pip install 'safestream-redactor[bench]'
python -m spacy download en_core_web_lg
python benchmarks/run_benchmark.py
```

The dataset generator is seeded (`--seed`) so runs are reproducible. Entities covered by
both tools are benchmarked: email, phone, credit card, SSN, IPv4.

Caveat: synthetic text is much friendlier than real-world data — treat absolute scores as
an upper bound and the tool-to-tool comparison as the meaningful signal.
