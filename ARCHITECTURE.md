# SafeStream-Redactor Architecture

This file explains how the redaction engine is built and why. It covers the tiered
detection cascade, the native core, the gated neural tier and the span resolver, and
it gives the measured performance. For the component diagrams see
[docs/architecture/](docs/architecture/); for a per-file walkthrough see
[docs/SYSTEM_ARCHITECTURE_AND_CODEBASE.md](docs/SYSTEM_ARCHITECTURE_AND_CODEBASE.md).

## 1. System overview and design philosophy

**Goal.** Redact PII and credentials from unbounded text streams (logs, exports,
documents) on one machine, with no network access, at high throughput and with
recall as close to 100% as the detectors allow. The design target is over
100 MB/s for the deterministic path. The measured figure is 59 MB/s on 8 workers on
a laptop running on battery (section 4).

**Why a single model does not work.** A transformer NER model reads about
1,000 tokens per second per CPU core (DistilBERT, about 86 MFLOP per token), which
is roughly 4 KB/s of text. A 1 GB log would take about three days per core. A model
also cannot be trusted with structured secrets: it has never seen most API key
formats, and it cannot check a Luhn digit or an IPv4 octet range.

**Why regular expressions alone do not work.** Patterns catch anything with a fixed
shape (keys, emails, card numbers, IPs). They do not catch a person's name in a
sentence, which has no fixed shape. On RedactionBench the deterministic tiers alone
cover 73.9% of the must-redact characters overall, but only 6.3% in legal documents
and 16.7% in medical ones.

**The approach: a cascade with a fast path and a gated neural path.** Every byte
goes through the cheap deterministic tiers (Tier 0). A cheap triage step (Tier 1)
picks out the small parts of the text that could contain a name. Only those parts
are sent to the neural model (Tier 2). A resolver merges the results so that a
deterministic detection always wins and no entity is left partly visible.

```
 text chunks ──> streaming engine (rolling buffer + overlap)
                        │
                        ├──> Tier 0  deterministic + labeled + entropy + contextual   (every byte)
                        │       native Rust core, or the pure-Python reference
                        │
                        ├──> Tier 1  micro-window gate (one regex pass, no inference)
                        │       │  ~6.3% of characters pass
                        │       ▼
                        │    Tier 2  ONNX INT8 DistilBERT NER (PER / ORG / LOC)
                        │
                        ▼
              confidence filter ──> resolve_overlaps (T0 wins, name spans union)
                        │
                        ▼
              redaction policy (replace / mask / pseudonymise / encrypt) ──> output
```

Tier 1 and Tier 2 are optional (`use_onnx=True` / `--onnx`). Without them the engine
is pure Tier 0 and needs no model.

## 2. Pipeline and tiers

### Streaming engine

`engine.py` keeps a rolling buffer of `chunk_size + overlap` characters. Each round
emits only the text at least `overlap` characters from the buffer's end, so any
entity up to `overlap` long (8 KB by default) is seen whole at least once, even when
a chunk boundary cuts through it. Each detector declares a `StreamingRequirements`
(longest span, left and right context), and the engine sizes the overlap from the
maximum across active detectors. Memory is bounded by `chunk_size + overlap + L_max`,
independent of input size. `parallel.py` splits one large file into ranges across
worker processes. Its output is byte-identical to the sequential pass, and a seam
cross-check falls back to sequential if the two ever disagree.

### Tier 0: deterministic native engine

| Part | Python module | Native (Rust) module |
| --- | --- | --- |
| Credential and PII patterns | `detectors/deterministic.py` | `native/src/patterns.rs` |
| Cards and phone numbers (lookaround semantics) | `detectors/deterministic.py` | `native/src/digits.rs` |
| Label-anchored identifiers (`Patient ID: …`) | `detectors/labeled_id.py` | `native/src/labeled.rs` |
| Entropy and compound secrets | `detectors/entropy.py` | `native/src/secrets.rs` |
| Contextual triggers and confidence adjust | `detectors/contextual.py` | `native/src/context.rs` |
| Byte to character offsets | — | `native/src/offsets.rs` |

**Rust core.** `native/` is a PyO3 0.22 crate built with maturin into an abi3 wheel
(one wheel per platform for CPython 3.10 and later). `Redactor(backend="native")`
or `--backend native` selects it. Its output is byte-identical to the Python tiers.

**SIMD literal prefilters.** Each pattern is compiled as its own `regex::Regex` and
scanned with `find_iter`, so the regex crate's required-literal prefilter (memchr /
Teddy, SIMD) jumps straight to candidate positions (`AKIA`, `eyJ`, `@`, `://`). A
single combined `RegexSet` was measured and rejected: about 6 MB/s against
400–1,200 MB/s per pattern, because the combined automaton loses the per-pattern
prefilters.

**Unicode word-boundary relaxation.** The Python patterns use Unicode `\b`, and the
native core must match them exactly. The fast lazy DFA cannot evaluate Unicode `\b`
on non-ASCII bytes and falls back to a slow engine, which cut throughput to under
1 MB/s on mixed text. `WordBounded` (`native/src/patterns.rs`) compiles each `\b`
rule twice:

1. a relaxed copy with every `\b` removed runs on the DFA to find candidate starts;
2. the exact `meta::Regex` verifies each candidate with an anchored search at that
   start (`Input::new(text).range(start..).anchored(Anchored::Yes)`).

Leftmost-first order is preserved, so matches are identical. After 64 rejected
candidates a rule switches to the exact regex, which keeps hostile input linear
(`test_hostile_non_ascii_runs_stay_linear`). Labeled identifiers went from 4.9 to
85.5 MB/s on mixed text, and `Redactor.detect` from 1.7 to 14.7 MB/s.

**Entropy scanning.** `EntropyDetector` finds runs over a fixed key alphabet and
scores them by length, character-class mix and Shannon entropy. It catches bespoke
tokens with no published format. `CompoundSecretDetector` covers runs with embedded
symbols (`! # $ % ^ & * ~`) that the base64-alphabet candidate splits on. The Rust
port carries an uncertainty band on each entropy value and defers to Python for the
rare value too close to the threshold, because CPython's float summation changed
in 3.12.

**Validators.** A pattern match becomes a detection only if it passes the
validator:

- Luhn for card numbers (`deterministic.luhn_ok`, `digits.rs::luhn_ok`);
- SSN area, group and serial rules;
- IPv4 octet ranges and `Ipv6Addr` parsing;
- MAC address group counts;
- E.164 phone shape.

The opt-in regional tier (`detectors/regional.py`, `use_regional=True`) adds:

- IBAN with ISO 7064 mod-97 plus the country's fixed length;
- Verhoeff for Aadhaar;
- mod-11 for NHS numbers.

The regional tier is Python-only.

**Python reference and parity.** The pure-Python tiers are the default backend, the
specification and the fallback. The native core checks at start-up that its
compiled pattern sources equal the Python ones (`_native_matches_spec`); if they
differ it is not used. In the rare ambiguous cases it hands the window back to
Python (`needs_python`): a lower-cased `İ`, or an entropy value near the threshold.
`tests/test_native_backend.py` runs both backends differentially on corpora and
fuzzed inputs.

### Tier 1: micro-window triage gate

Implemented in `detectors/onnx_ner.py` (`_candidate_windows`). It runs in Python as
one regex pass per text, with no inference.

**Why line gating failed.** The first gate sent every line containing a capitalised
word to the model. On the mixed benchmark corpus that was 35.5% of all characters,
because log lines are full of capitalised tokens.

**Micro-windows.** A window is opened only around a name-shaped candidate:

- a run of 2–4 Titlecase words (accented Latin and Cyrillic included);
- a single Titlecase word mid-sentence (`contact Alice`);
- the words after a person cue:
  - capitalised honorifics (`Dr.`, `Mr`, `Mrs`, `Dear`);
  - `signed by`;
  - sign-offs (`Regards,` reaches the name on the next line);
  - form labels ending in `:`, `–`, `—` or `►` (`patient:`, `name:`, `user:`,
    `contact:`, `witness:`, `agent:`, `doctor:`, `officer:`, `location:`,
    `surname –`).

Each window adds about 32 characters of context on each side, and overlapping
windows merge. Machine text (timestamps, hex, ALLCAPS log levels, paths, `k=v`
pairs, `cache=MISS`) triggers none of these. The share of characters reaching the
model drops from 35.5% to **6.29%**.

**Title-case normalisation.** The model is cased, so `signed by john smith` would
not read as a name. Lower-case words right after a cue are capitalised in the copy
the model reads. ALLCAPS words after a cue, and an ALLCAPS label itself, are
title-cased (`AGENT: TONY PRIZE` → `Agent: Tony Prize`); the model misses the
shouted form. ALLCAPS with no label (log levels, headers) still opens no window.
Each character keeps its length, so model offsets still index the original text.

**Known gate blind spot.** A lone sentence-initial first name (`Priya approved …`)
is not gated, because almost every sentence starts with a capital.

### Tier 2: gated INT8 ONNX NER

- **Model.** `dslim/distilbert-NER` (6-layer DistilBERT, CoNLL-03 tags PER, ORG, LOC
  and MISC). `scripts/export_onnx.py` exports it with dynamic batch and sequence
  axes and quantises it dynamically to INT8 (261 MB to 66 MB). Any BIO
  token-classification ONNX model works with `--onnx-labels`. MISC is not mapped
  to an entity type. Other model families such as GLiNER are not implemented.
- **Runtime.** `onnxruntime` CPU provider only, so no data leaves the machine.
  Each session uses `intra_op_num_threads=1`, `ORT_SEQUENTIAL` and `ORT_ENABLE_ALL`;
  parallelism comes from worker processes (`--workers`), not threads inside one
  session.
- **Batching.** Windows are sorted by length and run as padded batches of up to 32
  rows per session call. Softmax and argmax are NumPy array operations over the
  whole batch.
- **Tokenisation and alignment.** The Hugging Face fast tokenizer
  (`tokenizers`, `tokenizer.json`) returns character offsets for every sub-word,
  so spans map straight back to the source text. `decode_bio` merges tags into
  spans:
  - a sub-word span is widened to the whole word (`_snap_to_words`);
  - a `B-` tag glued to the previous sub-word continues the span;
  - name parts separated only by a space become one redaction (`_join_spaced`).
- **Scoring.** A span's confidence is the mean of its token probabilities, so one
  uncertain sub-word cannot veto a name. The acceptance threshold is τ = 0.35.
  Accepted spans are emitted at confidence `max(score, 0.5)`, so the pipeline's
  default `min_confidence` of 0.5 does not undo the lower threshold. The raw score
  is kept in `meta["onnx_score"]`.

### Span resolver and redaction

`entities.resolve_overlaps` turns all detections into a sorted, non-overlapping
list:

1. Detections that overlap one another form clusters.
2. A cluster with no NER member (sources `ner`, `onnx`, `gazetteer_name`,
   `semantic_ensemble`) is resolved greedily: the most specific, highest-confidence
   span wins.
3. A cluster that contains an NER span becomes **one span from `min(start)` to
   `max(end)`**. It takes the label of its best Tier 0 member if it has one, and
   otherwise its best member's label.

This rule stops two leaks:

- A `PERSON` tag on `john.doe` cannot shrink the redaction of
  `john.doe@example.com` and leave `@example.com` visible. The union covers the
  whole email and keeps the `email` type.
- `Priya` (PERSON) inside `Priya Iyer` (ORG) cannot win alone and leave `Iyer`
  visible.

The cost is a little over-redaction at the edges, by design.

`RedactionPolicy.apply` then rebuilds the text in one left-to-right pass:

- it copies the text between detections and inserts the rendered replacement
  (`[REDACTED]`, a mask, a pseudonym or ciphertext);
- offsets are Python character offsets; the native core converts its UTF-8 byte
  offsets once per window, so multi-byte text never splits inside a character;
- the result is assembled with `"".join`. Python strings are immutable, so this is
  a single linear copy, not an in-place edit.

## 3. Repository map

```
SafeStream-Redactor/
├── src/safestream_redactor/      Python package (the reference implementation)
│   ├── redactor.py               Redactor: builds the tier list, detect/redact/stream/file APIs
│   ├── engine.py                 streaming windows, overlap sizing, boundary retreat
│   ├── parallel.py               one file split across processes, seam cross-check
│   ├── scheduler.py              RAM/CPU-aware parallelism across a directory tree
│   ├── entities.py               EntityType, Detection, resolve_overlaps (union rule)
│   ├── policy.py, operators.py   replacement, masking, pseudonyms, reversible encryption
│   ├── cli.py, api.py, mcp_server.py   CLI, REST API, offline MCP tools
│   ├── netguard.py, netguard_hard.py   offline guarantee (socket guard, seccomp/netns)
│   └── detectors/
│       ├── deterministic.py      Tier 0 patterns and validators (+ native bridge NativeBacked)
│       ├── labeled_id.py         label-anchored identifiers
│       ├── entropy.py            entropy and compound-secret tiers
│       ├── contextual.py         trigger-word confidence adjustment
│       ├── regional.py           opt-in IBAN / Aadhaar / NHS / NINO / PAN / crypto
│       ├── onnx_ner.py           Tier 1 gate + Tier 2 ONNX NER
│       ├── ner.py                alternative spaCy NER tier
│       └── gazetteer_ner.py, semantic_ensemble.py   model-free name heuristics
├── native/                       Rust crate safestream_native (PyO3 + maturin, abi3)
│   ├── src/patterns.rs           pattern table, WordBounded fast path, validators
│   ├── src/digits.rs             linear-time card / phone scanners
│   ├── src/labeled.rs            labeled-identifier rules
│   ├── src/secrets.rs            entropy and compound-secret tiers
│   ├── src/context.rs            contextual tier
│   ├── src/offsets.rs            byte to char offset map
│   ├── src/python.rs             PyO3 bindings
│   ├── benches/, examples/       criterion benches and profiling drivers
│   └── tests/                    Rust-side tests
├── benchmarks/
│   ├── tiered_bench.py           T0 vs T0+ONNX: recall, latency, worker scaling
│   ├── redactionbench/           RedactionBench loader, adapter, char/span metrics, reports
│   ├── presidio_compare.py       like-for-like comparison with Presidio
│   └── baseline.py, scale_memory.py, native_backend.py   throughput and memory curves
├── scripts/export_onnx.py        HF checkpoint -> ONNX (dynamic axes) -> INT8 + tokenizer.json
├── tests/                        pytest suite
│   ├── test_native_backend.py    Python/Rust differential parity, fuzzed inputs
│   ├── test_recall_vectors.py    zero-miss regression vectors (structured + names + gate)
│   ├── test_properties.py        Hypothesis properties (no partial leak, streaming = whole)
│   └── test_onnx_ner*.py         decoder, gate and real-model inference tests
├── research/results/             recorded runs (raw JSON, RedactionBench reports)
├── docs/                         design notes (NATIVE_CORE, DETECTORS, MEMORY_ARCHITECTURE, …)
└── models/                       exported ONNX models (git-ignored, made by export_onnx.py)
```

## 4. Performance

> **Not reproduced (2026-10-03).** The figures below come from an earlier harness and
> environment and were not reproduced by the Phase 0 baseline (`benchmarks/harness.py`,
> isolated per-tool virtualenvs, one thread per tool, dev splits). Treat them as
> historical. Current measured numbers: the README's Evaluation section and
> [`research/reports/gap-report.md`](research/reports/gap-report.md).

Measured 2026-10-03 on an Intel i7-12650H (10 cores, 16 threads), Windows 11,
Python 3.14, **on battery** with the Balanced power plan. Absolute numbers are
pessimistic; the scaling shape is the useful part. Raw data:
[research/results/raw/tiered_2026-10-03.json](research/results/raw/tiered_2026-10-03.json).

### Throughput and latency (`benchmarks/tiered_bench.py`)

The corpus is synthetic and seeded: 80% logs, the rest prose, structured records and
name-bearing text. The figures are for the full pipeline, not one regex.

| Config | 1 worker | 4 workers | 8 workers | 16 workers | Latency per 64 KiB, p50 / p99 |
| --- | --: | --: | --: | --: | --: |
| T0 (native) | 5.9 MB/s | 31.8 MB/s | 59.2 MB/s | 58.0 MB/s | 3.6 / 6.4 ms |
| T0 + gated ONNX | 0.04 MB/s | 0.11 MB/s | 0.11 MB/s | 0.11 MB/s | 2.5 / 3.5 s |

- T0 scales almost linearly up to the 10 physical cores. 16 workers adds nothing
  over 8 because of hyper-threads and the battery power cap.
- T0+ONNX is limited by the model: 6.29% of characters reach it, and it reads about
  4 KB/s per core. Use it for prose, not bulk logs.
- Strict full-span recall on this corpus:
  - structured PII and secrets: 0.9997 (3322 of 3323), in both configs. The one
    miss is a letters-only random secret, which the entropy tier skips by design.
  - person names: 0.9997 with ONNX (3226 of 3227), 0 without.

### RedactionBench (200 real documents)

These figures come from the repo's own **character-level** re-implementation of the
metric (`benchmarks/redactionbench/metrics.py`). They are **not** the official
leaderboard R-Score, whose scorer has not been released.

| Config | Char precision | Char recall | Char F1 | Mandatory recall | Contextual recall | Docs with no mandatory leak | Runtime |
| --- | --: | --: | --: | --: | --: | --: | --: |
| T0 | 0.767 | 0.447 | 0.565 | 0.759 | 0.211 | 14.0% | 10.8 s |
| T0 + gated ONNX | 0.685 | 0.545 | 0.607 | 0.823 | 0.335 | 21.5% | 156.2 s |

Both runs were on battery; runtime varies by a factor of two or more between runs in
that state, so compare the two configs, not runs on different days.

Mandatory character recall by domain, T0 → T0+ONNX:

| Technical domains | | Prose domains | |
| --- | --- | --- | --- |
| logs | 0.907 → 0.927 | academic | 0.258 → 0.857 |
| terminal | 0.830 → 0.861 | legal | 0.340 → 0.782 |
| code | 0.776 → 0.800 | medical | 0.244 → 0.752 |
| files | 0.718 → 0.739 | operations | 0.361 → 0.719 |
| | | emails | 0.418 → 0.700 |
| | | government | 0.346 → 0.695 |
| | | financial | 0.381 → 0.690 |

The model adds little where text is structured and is decisive in prose.

**What the address and form rules added.** Before the postal-address patterns, the
case/docket/policy/claim/visa/record labels, the form separators and the ALLCAPS
gate (same day, same harness), T0+ONNX mandatory recall was 0.815, legal 0.651 and
medical 0.724; T0 alone had legal at 0.063.

**Remaining gaps.**

- identifiers with no label next to them, or with words between the label and the
  value (`Record Number (if any): ► …`);
- non-US addresses (`PUNE, MAHARASHTRA - 411045`);
- MISC-tagged spans, which are not mapped to an entity type;
- `name=value` pairs that the entropy tier reads as one token;
- letters-only secrets;
- bcrypt hashes (the `.` stays visible);
- keys containing `_test_`, skipped as placeholders.

## 5. Getting started

### Build

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,onnx]"

# native core (needs a Rust toolchain: https://rustup.rs)
pip install maturin
cd native && maturin develop -r && cd ..

# optional: export the NER model once (needs torch + transformers)
python scripts/export_onnx.py --out models/ner

pytest -q
```

### CLI

```bash
# Tier 0 on the native core, one large file split across 8 workers
safestream redact huge.log -o huge.clean.log --backend native --workers 8

# Tier 0 + gated ONNX names
safestream redact notes.txt -o notes.clean.txt --backend native --workers 8 \
    --onnx models/ner/model.int8.onnx --onnx-vocab models/ner/tokenizer.json \
    --onnx-labels models/ner/labels.json

# list detections without redacting (matched text hidden by default)
safestream detect notes.txt --backend native
```

### Python streaming API

```python
from safestream_redactor import Redactor

redactor = Redactor(
    backend="native",                         # falls back to Python if the wheel is absent
    use_onnx=True,                            # Tier 1 gate + Tier 2 model
    onnx_model="models/ner/model.int8.onnx",
    onnx_vocab="models/ner/tokenizer.json",
    onnx_labels="models/ner/labels.json",
)

redactor.redact("signed by john smith, key AKIAIOSFODNN7EXAMPLE")
# 'signed by [REDACTED], key [REDACTED]'

# constant memory over any iterable of chunks; entities split across chunk
# boundaries are still caught (overlap window)
with open("huge.log", encoding="utf-8") as src, open("huge.clean.log", "w", encoding="utf-8") as dst:
    for clean in redactor.redact_stream(iter(lambda: src.read(1 << 16), "")):
        dst.write(clean)

# file to file, atomic write, optional multi-process split
stats = redactor.redact_file("huge.log", "huge.clean.log", workers=8)
print(stats.summary())
```
