# Benchmarks

Two distinct things live here, and conflating them is the mistake to avoid:

- **`run_benchmark.py` — a regression fixture, NOT an accuracy measure.** It scores the
  detector against *self-generated* synthetic text whose gold positives use the same
  canonical formats the detector targets. A near-perfect score there means "still
  handles standard formats and resists these distractors," not "accurate on real data."
  Use it to catch regressions and to compare false-positive resistance against Presidio.
- **`evaluate.py` — the real accuracy harness.** Point it at an *independent* labeled
  corpus you did not generate; the precision/recall it reports are defensible. This is
  the only number to quote when someone asks "how accurate is it?"

## Real accuracy: `evaluate.py`

Nothing is bundled (these corpora carry their own licenses). Recommended targets:

- **[Presidio research dataset](https://github.com/microsoft/presidio-research)** —
  PII in generated-but-realistic sentences with a standard label set.
- **CoNLL-2003 / WikiNER** — PERSON/ORG/LOC recall (needs the `[ner]` extra to be
  meaningful; the regex core does not detect names).
- **n2c2 / i2b2 de-identification** — clinical PHI, the hardest and most valuable target
  (requires a data-use agreement).

Convert the corpus to either shape the harness accepts (a `--text`/`--gold` pair, or a
`--jsonl` of `{text, spans}`), map its labels onto SafeStream types, and run:

```bash
python benchmarks/evaluate.py --jsonl corpus.jsonl \
    --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn,CREDIT_CARD=credit_card --ner
```

It reports per-type and micro-averaged precision/recall/F1. Expect recall on free-form
names/addresses to be far below the synthetic numbers unless `--ner` is on — that gap
is the honest state of a regex-first detector and is what the roadmap's calibration and
NER work targets.

## Regression fixture: `run_benchmark.py`

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

Caveats (why this is a fixture, not an accuracy result):

- The gold positives are generated from the same standard formats the detector targets,
  so recall on them is close to circular — it cannot tell you real-world recall. Only
  `evaluate.py` against an independent corpus can.
- The genuinely informative signal here is **precision under distractors** (the
  adversarial corpus) and **throughput**, both of which compare fairly against Presidio.
- Structured PII only. SafeStream's credential/secret tiers (AWS/GitHub/Slack/Stripe/
  entropy secrets) have no Presidio equivalent — see the credentials note in the
  top-level README.

Both dataset generators are seeded (`--seed`) so CI can regenerate and gate on them
(`run_benchmark.py --assert-precision/--assert-recall`).
