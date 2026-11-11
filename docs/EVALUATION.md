# Evaluation

Measured accuracy and throughput of SafeStream-Redactor against Presidio, and what the
numbers do and do not show. The README carries a short summary. This page has the
tables, the conditions they were measured under, and where SafeStream loses.

> **Read this before quoting any number below.** These are **Phase 0 dev-split**
> results: tuning happens on dev, and the held-out test splits are scored once, at the
> end of the work. Every number comes from one run of `benchmarks/harness.py`
> (commit `cebe741`, 2026-10-03) on an i7-12650H under Windows 11 on AC power in the
> *Best power efficiency* power mode, with every tool in its own virtualenv and pinned
> to **one thread**. Absolute speeds are therefore throttled; ratios between tools come
> from the same run and the same conditions. Raw JSON and tables:
> [`research/results/raw/`](../research/results/raw/); analysis and error examples:
> [`research/reports/gap-report.md`](../research/reports/gap-report.md).

**Corpora.** The headline sets are independent of this repo: the
[presidio-research](https://github.com/data-privacy-stack/presidio-research) synthetic
dataset (750 dev documents), the English validation set of AI4Privacy
pii-masking-300k (3,973 dev documents; academic licence, acknowledgement: AI4Privacy)
and a secrets corpus of real-format credentials from
[Nosey Parker](https://github.com/praetorian-inc/noseyparker)'s rule examples plus
generated non-secrets (313 dev documents). RedactionBench is reported as **previously
exposed**: all 200 documents were used to tune rules before the split existed. CoNLL-2003
is **not independent for the ONNX tier**: its model was trained on CoNLL. 95% CIs are
document bootstrap; P / R / F1 are character-level (did the sensitive characters get
hidden?). "Full" is the share of gold entities with *every* character redacted.

**Pattern tier** (no ML on either side; SafeStream's rule tiers against Presidio's own
pattern and checksum recognizers called directly):

| Corpus | SafeStream (native) char F1 | Presidio-regex char F1 | SafeStream P / R | Presidio P / R | Speed |
| --- | --- | --- | --- | --- | --- |
| presidio-research | 0.278 [0.243, 0.314] | 0.303 [0.267, 0.338] | 0.992 / 0.162 | 0.915 / 0.181 | 27× |
| ai4privacy | 0.467 [0.453, 0.480] | **0.553** [0.542, 0.563] | 0.966 / 0.308 | 0.747 / 0.439 | 63× |
| ai4privacy, `--dates` | **0.581** [0.570, 0.592] | 0.553 [0.542, 0.563] | 0.956 / 0.418 | 0.747 / 0.439 | 24× |
| secrets | **0.637** [0.560, 0.706] | 0.215 [0.152, 0.287] | 0.524 / 0.814 | 0.292 / 0.171 | 80× |
| RedactionBench (exposed) | **0.556** [0.479, 0.622] | 0.331 [0.289, 0.372] | 0.730 / 0.449 | 0.356 / 0.310 | 169× |

SafeStream is far more precise and 24–169× faster per core, but **Presidio-regex has
the higher F1 on ai4privacy** with the default configuration (it detects dates, URLs,
IBANs and digit-run IDs that the default tier does not) and the two are level on
presidio-research.

**NER tier** (SafeStream: native rules + gated on-device ONNX `dslim/distilbert-NER`,
INT8; Presidio: its full engine on spaCy `en_core_web_sm` / `_lg` and on two
transformers models). Best Presidio per corpus shown; all configurations are in the
raw tables.

| Corpus | SafeStream + ONNX char F1 | Best Presidio char F1 | Full (SafeStream / Presidio) | Speed vs `presidio-sm` | Tool memory |
| --- | --- | --- | --- | --- | --- |
| presidio-research | **0.718** [0.693, 0.742] | 0.708 [0.686, 0.728] (trf-deid) | 0.500 / 0.545 | 1.9× | 151 / 127 MB |
| ai4privacy | 0.576 [0.566, 0.586] | **0.733** [0.726, 0.740] (trf-deid) | 0.338 / **0.607** | 0.74× | invalid† |
| secrets | 0.636 [0.560, 0.705] | 0.596 [0.526, 0.658] (trf-deid) | 0.542 / **0.735** | 4.7× | 153 / 127 MB |
| RedactionBench (exposed) | **0.611** [0.531, 0.662] | 0.460 [0.394, 0.520] (trf-deid) | 0.608 / **0.727** | 1.4× | 150 / 205 MB |
| CoNLL (not independent) | 0.796 [0.770, 0.818] | 0.652 [0.609, 0.691] (trf-bert) | 0.648 / 0.651 | 0.32× | 150 / 130 MB |

† Each tool's process also parsed the whole ai4privacy file, and that transient peak
dominates every system's RSS there.

**Where SafeStream loses today:** Presidio's transformers engine redacts more entities
*fully* on every headline corpus (it also flags every secret-free document in the
secrets set), and wins ai4privacy outright: SafeStream misses values inside structured
fields (`"LastName": "…"`, `<Phone>…</Phone>`, `Postcode: '…'`), unlabelled ID numbers,
most international phone formats and many names. Presidio's transformers engine is
also 13–86× *slower* per core than the ONNX tier on the prose corpora. Mandatory recall on RedactionBench is
0.875 [0.761, 0.936] for SafeStream + ONNX and 0.908 [0.825, 0.958] for Presidio-trf-deid.

**Secrets.** 54.2% [48.1, 60.6] of real-format secrets are fully redacted by the
pattern tier (Presidio-regex: 13.1%); 119 of 260 dev secrets leak, mostly vendor keys
without a detector, connection strings and `password = '…'` assignments, and the
entropy tier flags 81% of generated UUIDs, hashes and base64 images. Both are the first
targets of the current work.

**Throughput.** One thread, per-document streaming detection, power-saving mode:

| Corpus | Pure Python | Native core | Native + ONNX |
| --- | --: | --: | --: |
| RedactionBench (long prose) | 1.23 MB/s | 10.9 MB/s | 0.032 MB/s |
| ai4privacy (short records) | 1.39 MB/s | 9.54 MB/s | 0.020 MB/s |
| CoNLL (news) | 1.40 MB/s | 16.6 MB/s | 0.0074 MB/s |
| presidio-research (one sentence per document) | 1.10 MB/s | 3.02 MB/s | 0.013 MB/s |

The native core is 3–12× pure Python, and the ONNX tier is model-bound (it is for
prose, not bulk logs).

**Throughput, Best performance mode, 1 thread / 16 threads** (`benchmarks/throughput.py`,
a fixed ~2 MB dev sample per corpus, 120 s budget per run; raw data in
[`research/results/raw/2026-10-03_throughput.json`](../research/results/raw/2026-10-03_throughput.json)):

| System | presidio-research | ai4privacy | RedactionBench | CoNLL |
| --- | --: | --: | --: | --: |
| SafeStream native | 6.61 / 6.55 MB/s | 14.0 / 13.3 | 17.2 / 18.1 | 27.2 / 27.4 |
| SafeStream + ONNX | 0.013 / 0.020 | 0.015 / 0.051 | 0.023 / 0.096 | 0.0095 / 0.037 |
| Presidio regex | 0.125 / 0.138 | 0.136 / 0.145 | 0.058 / 0.063 | 0.092 / 0.090 |
| Presidio `sm` | 0.015 / 0.013 | 0.023 / 0.023 | 0.020 / 0.020 | 0.020 / 0.021 |
| Presidio transformers (de-id model) | 0.0007 / 0.0024 | 0.0010 / 0.0047 | 0.0008 / 0.0039 | 0.0009 / 0.0032 |

Threads help only the model runtimes: Presidio's transformers engine gains 3–5×, the
ONNX tier 1.6–4×; at equal threads the ONNX tier stays 8–30× faster than it. SafeStream's
own multi-core path is processes (`--workers N`), not threads; its scaling is not yet
re-measured, and earlier single-file figures (10–35 MB/s per core, 36–121 MB/s on 4
workers, 5.9 → 59 MB/s on 1 → 8 workers) came from other machines or a battery run and
are not quoted until it is. A Vectorscan/re2
backend was prototyped and rejected
([docs/PERFORMANCE_BACKENDS.md](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/PERFORMANCE_BACKENDS.md)).

**ONNX inference is one window per call by default.** An INT8 model made by dynamic
quantization scores a window differently depending on the other windows in its batch,
which made output depend on chunking (and parallel differ from sequential).
`--onnx-batch-size N` restores batching as an explicit, non-deterministic opt-in; on
the dev corpora above it changed speed by −15% to +32% with no consistent direction and
accuracy by under 0.01 F1, so nothing is lost by the deterministic default.

> **Reproducible results & comparison.** Measured accuracy/throughput and a
> constant-memory scaling curve — each recorded with full environment metadata and the
> exact command to reproduce it — plus a documented capability matrix against 10 systems
> (Presidio, Philter, Piiranha, GLiNER, Grepture, Private AI, AWS Comprehend, Google DLP,
> Microsoft Purview, Tonic AI) live in [`research/`](https://github.com/MounishSenisetty/SafeStream-Redactor/tree/main/research). Only SafeStream's numbers
> are measured; competitor rows are labelled *documented*. A complete per-file walkthrough
> of the whole project is in [`docs/PROJECT_OVERVIEW.md`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/docs/PROJECT_OVERVIEW.md).

## Detection accuracy and limitations

**100% recall and 100% precision together are not achievable for free-text PII, by
anyone.** Names, street addresses, bank account numbers, and employee IDs have no
distinctive form — a bank account number is indistinguishable from any other run of
digits, and "April" is both a name and a month. Any detector faces a precision/recall
tradeoff: catch every possible name and you also redact ordinary words; redact only
unambiguous matches and you miss the rest. SafeStream is tuned to favour precision on
structured PII and credentials, with names and format-less identifiers handled by the
opt-in levers below. Treat it as high-recall for credentials and structured PII, and
best-effort for free prose — not as a guarantee of catching everything.

**Placeholder words near a value.** The contextual tier *subtracts* confidence from a
value when the whole word `test`, `sample`, `example`, `dummy`, `fake`, `placeholder`,
or `lorem` sits in or just before it (see `detectors/contextual.py`), so documentation
snippets and fixture data are not redacted. Only shape-only matches are demoted (a bare
SSN, phone, email, IP or high-entropy string). Vendor-prefixed keys (`sk_test_…`),
checksum-validated numbers (cards, IBANs), field- or label-anchored values
(`password: …`) and NER names are never demoted, and words that merely contain a
trigger (`latest`, `protest`, `TestPass`) do not count. If you *want* the demoted values
redacted anyway, lower `min_confidence` (below).

**Three levers to raise recall**, in increasing order of effort:

1. **Lower `min_confidence`.** The default is 0.5. Setting it to `0.35`
   (`--min-confidence 0.35`, or in a policy file) recovers most values the test/sample
   suppression demotes, at some cost to precision. Do this per-run on data you know is
   noisy — not globally on trusted prose.
2. **Enable NER for names.** Person / org / location names need the optional spaCy tier:
   `pip install 'safestream-redactor[ner]'` then `python -m spacy download en_core_web_sm`,
   and run with `--ner` (or `use_ner = true` in a policy). Without it, names are not
   detected at all.
3. **Add custom patterns for format-less identifiers.** Passport numbers, driver
   licences, bank/routing/account numbers, employee IDs, Slack user IDs, and dates of
   birth have no universal signature, so they need label-anchored regexes you supply. A
   ready-to-use policy covering all of these ships in
   [`examples/policy.toml`](https://github.com/MounishSenisetty/SafeStream-Redactor/blob/main/examples/policy.toml):

   ```bash
   safestream detect input.txt --config examples/policy.toml
   ```

   It also enables NER and documents each lever inline. Custom patterns redact the whole
   match (including the label word) — the fail-safe outcome for DLP.
