# Benchmarks

Compares SafeStream-Redactor against [Microsoft Presidio](https://github.com/microsoft/presidio)
on a synthetic, labeled dataset: precision / recall / F1 (type-aware, ≥50% span overlap)
and raw throughput in MB/s.

```bash
# 1. generate a labeled corpus (default 10 MB -> benchmarks/data/)
python benchmarks/generate_dataset.py --size-mb 10

# 2. run
python benchmarks/run_benchmark.py

# optional: include Presidio in the comparison (no model download needed —
# the compared types are pattern-based in Presidio and run fully offline)
pip install 'safestream-redactor[bench]'
python benchmarks/run_benchmark.py
```

The dataset generator is seeded (`--seed`) so runs are reproducible. Entities covered by
both tools are benchmarked: email, phone, credit card, SSN, IPv4. Presidio is exercised
through its own pattern recognizers, so no ~600 MB spaCy model is required.

Caveats:

- Synthetic text is much friendlier than real-world data, and the corpus is generated from
  standard entity formats, which favours any regex-based detector. Treat SafeStream's
  scores as *"handles standard PII cleanly"* rather than a blanket accuracy claim.
- This benchmark covers **structured PII only**. SafeStream's credential/secret tiers
  (AWS/GitHub/Slack/Stripe/entropy secrets) have no Presidio equivalent and are its main
  differentiator — see the credentials comparison in the top-level README.
