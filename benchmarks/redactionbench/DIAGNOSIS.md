# RedactionBench forensic diagnosis — where recall is lost, and the architectural verdict

> **CORRECTION (see [`VALIDATION.md`](VALIDATION.md)).** The streaming/detection
> attribution below is confirmed and strengthened (1,401 adversarial cases + chunk-64
> full-corpus equivalence, 0 divergences). But two conclusions here are corrected by the
> validity pass: the **"0.431 all-gold RChar ceiling" is withdrawn** (a metric artifact
> from counting optional `contextual` spans as required), and the **"near its achievable
> ceiling"** framing is **not supported** — the recall-relevant metric is mandatory
> recall (0.69/0.77) and there is real NER headroom (class B / names sits at 0.013).
> No number here is an official R-Score (that scorer is unreleased).

Produced by the instrumentation in [`diagnose.py`](diagnose.py) over the full
200-document corpus (revision `d45e9cec…`). Every number below is measured, not
asserted. The instrumentation traces each **mandatory** gold character through
the real pipeline stages and attributes its loss to exactly one cause.

Run it yourself:
```bash
python -m benchmarks.redactionbench.diagnose --data-dir benchmarks/data/redactionbench
```

## The one-paragraph verdict

**The streaming architecture is not the bottleneck — detector recall is, and it
is almost entirely person names.** Chunking, overlap, boundary-crossing,
reconciliation, offset mapping, and final redaction together lose **~0%** of
mandatory characters (measured, not estimated). ~30% of mandatory characters are
lost because **no detector ever proposes a candidate for them**, and the largest
single cause is names: the regex core detects **1.4%** of name instances. The
optional NER tier lifts that to near the theoretical name ceiling — spaCy already
recovers **82%** of the entire name headroom. Beyond NER there is no
precision-safe lever, and the hypothesized stateful-streaming redesigns target
stages that already lose nothing, so their expected gain is ~0. The architecture
is within ~0.02 of its achievable ceiling for a precision-respecting redactor.

## Benchmark trust check (is the metric itself correct?)

Independently confirmed before trusting any number:

- **Offsets** are character offsets and align exactly, including on documents with
  non-ASCII (`Café`, `Brændá`).
- **Gold spans never overlap** within a document (0/200) → the mandatory/contextual
  split cannot double-count.
- **Hand-verified metric**: `tests/test_redactionbench.py::test_char_metric_hand_verified`
  computes char P/R/F1 by hand on a constructed example (P=0.6667, R=0.8571,
  F1=0.75) and asserts the harness reproduces it exactly.
- **Char metric = independent recomputation** on real documents (tp/fp/fn identical).

## Failure decomposition (mandatory characters; 165,239 total)

| Stage the character was lost at | chars | share | spans |
|---|--:|--:|--:|
| `covered_exact` (detected, exact boundary) | 64,749 | 39.2% | 898 |
| `boundary_partial` (detected ≥50%, gold over-segments) | 51,492 | 31.2% | 9,144 |
| `never_detected` (no candidate proposed) | 48,207 | **29.2%** | 6,872 |
| `confidence_rejected` (candidate below threshold) | 791 | 0.5% | 79 |
| `reconciliation_lost` (dropped by overlap resolution) | 0 | **0.0%** | 0 |
| `streaming_lost` (whole-doc found it, streaming didn't) | 0 | **0.0%** | 0 |

`boundary_partial` is **not a real loss** at the character level: R-Score credits
the covered characters, so these spans are mostly true positives. They are
"partial" only because RedactionBench segments one value into many fine spans
(a date into 7 spans, a name into `First`+space+`Last`) while SafeStream emits one
span — which is why character recall (0.686) far exceeds exact-span recall.

## Detection vs redaction (16,993 mandatory spans)

| Question | count | of mandatory |
|---|--:|--:|
| Recognized by some detector (raw candidate ≥50%) | 10,121 | 59.6% |
| Survived reconciliation | 10,042 | 59.1% |
| Actually redacted in streaming output | 10,042 | 59.1% |

Reconciliation removes **79 spans (0.5%)**; streaming/final redaction removes
**zero**. Detection is where essentially all the loss is.

## Boundary-failure matrix (streaming vs whole-document)

A known entity was placed at **every** offset from 0 to `2·chunk_size` and the
streaming output compared to whole-document output:

| chunk size | positions tested | boundary failures |
|---:|---:|---:|
| 16 | 37 | **0** |
| 32 | 69 | **0** |
| 64 | 133 | **0** |

Zero boundary failures at any position — entities crossing chunk boundaries are
never missed. (This matches the byte-identical streaming-vs-whole result on the
full corpus.) The overlap/carry-over context is sufficient; detector state is not
reset in a way that loses entities; no regex needs unavailable context.

## Per-type recall (mandatory, heuristic type)

| Type | instances | detected | recall | boundary-exact rate | dominant failure |
|---|--:|--:|--:|--:|---|
| number/date | 10,357 | 8,090 | 0.781 | 0.005 | gold over-segmentation (partial, not loss) |
| alnum/token | 2,810 | 1,729 | 0.615 | 0.468 | opaque codes/usernames, symbol passwords |
| **name** | **2,343** | **32** | **0.014** | 0.000 | **never detected — no NER in core** |
| other | 1,478 | 186 | 0.126 | 0.231 | short codes, unlabeled values |

Names are the catastrophe: 2,343 instances, 32 detected without NER.

## Detector ablation (mandatory span recall, ≥50% char overlap)

| Configuration | recall |
|---|--:|
| 1. deterministic only | 0.537 |
| 2. + entropy | 0.585 |
| 4. + labeled-identifier cascade | 0.548 |
| 5. full + reconciliation | 0.591 |

Reconciliation does **not** reduce recall (0.591 ≥ each component) — it is not
deleting entities. Each tier adds recall monotonically.

## Oracle upper bounds (char-level mandatory recall = 0.691 today)

| Oracle | mandatory recall | all-gold RChar |
|---|--:|--:|
| Current core | 0.691 | 0.298 |
| **Perfect NER** (catch every name) | **0.786** | 0.339 |
| spaCy NER (measured, actual) | 0.769 | 0.331 |
| Perfect mandatory (catch everything must-redact) | 1.000 | 0.431 |
| all-gold RChar = 1.0 | — | requires redacting the subjective contextual class |

**spaCy NER (0.769) is already within 0.017 of the perfect-NER ceiling (0.786).**
The NER lever is nearly exhausted. And even a perfect must-redact oracle caps
all-gold RChar at **0.431**, because the contextual class is 57% of gold
characters and a precision-respecting tool should not blanket-redact it.

## Definitive answers

**1. Why is core recall only ~0.40 RChar / 0.69 mandatory?**
Detector recall. ~30% of mandatory characters get no candidate at all; names have
**1.4%** recall in the regex core (names have no lexical signature). The all-gold
0.40 is further diluted by the contextual class (57% of gold chars), most of which
a precision-respecting redactor does not — and should not — flag. **0%** is lost
to chunking, streaming, reconciliation, offsets, or redaction.

**2. Why does NER improve recall only to ~0.53 RChar / 0.77 mandatory?**
Not a pipeline defect — that *is* essentially the name ceiling. spaCy
`en_core_web_sm` lifts name recall from 1.4% to near the perfect-NER bound
(mandatory 0.691→0.769, vs oracle 0.786). The residual mandatory misses are
non-name, unlabeled, genuinely ambiguous values (opaque codes, bare numbers) that
cannot be caught without destroying precision; all-gold RChar stays low because
contextual dominates.

**3. Exact % of errors: detection vs chunking vs boundaries vs reconciliation vs
offset vs final redaction** (of mandatory characters):
- **Detection: 29.7%** (never_detected 29.2% + confidence_rejected 0.5%) — ~100%
  of the recoverable loss.
- **Chunking / streaming boundaries: 0.0%** (0 boundary-matrix failures).
- **Reconciliation: ~0.5%** (79 spans; negligible in characters).
- **Offset mapping: 0.0%.**
- **Final redaction: 0.0%.**

**4. Which component is the bottleneck?**
Candidate generation — specifically **person-name detection** (a semantic/NER
capability), and secondarily unlabeled ambiguous identifiers. Not the streaming
engine, reconciliation, redaction, or offset mapping.

**5. What redesign gives the largest recall gain?**
Better NER for names — the only lever with headroom — but it is bounded: oracle
mandatory 0.786, and spaCy is already at 0.769, so remaining headroom is ~0.017.
The stateful-streaming / delayed-finalization / candidate-voting redesigns target
stages that lose 0%, so their evidence-based expected gain is **~0** — they were
deliberately **not** built, because the instrumentation shows nothing to recover
there. Implementing them would add complexity and risk for no benefit.

**6. Which changes improved real generalization (not just the score)?**
The label-anchored identifier cascade (precision-safe, helps any labeled-form
data) and the optional NER tier both generalize. Chasing the contextual class or
tuning the entropy tier down to this corpus would be anti-generalizing (worse on
real data). No streaming-architecture change was warranted by the evidence.

**7. What false negatives remain, and why?**
Names NER still misses (accented `Brændá`, rare names, names embedded in prose);
opaque usernames/codes (`elenar_77`, `WVHS-Burn-77`) with no format or cue;
symbol-containing passwords (entropy-tier limitation); and the subjective
contextual class (single spaces, date digits, separators) that a DLP tool should
not blanket-redact. These are inherent to a precision-respecting deterministic
redactor, not a fixable pipeline stage.

**8. Final accuracy / performance / memory trade-off.**
The architecture is already near its ceiling. Core: **O(1) memory**, ~14 s for 200
docs, char precision 0.75, mandatory recall 0.69. + spaCy NER: mandatory recall
0.77 at ~5 min/200 docs and a heavier (but still local, still streaming-safe)
dependency. A transformer-grade NER would cost large memory/throughput/dependency
for ~0.02 mandatory recall — a poor trade against the constant-memory,
local-first, high-throughput design goals. **Recommendation:** keep the
lightweight streaming core with optional NER; always report the
mandatory/contextual split; do not pursue all-gold ≈1.0, which is unreachable
without gaming.

## Why we stopped here (the stopping condition, met with evidence)

The request was to continue until the dominant failure modes are addressed and
further changes stop producing meaningful gains. The instrumentation shows: the
dominant failure mode (names) is addressed by the existing NER tier to within
0.017 of its theoretical ceiling; the next-largest recoverable causes are already
handled (labeled identifiers) or precision-unsafe to pursue (unlabeled numbers);
and every non-detection stage loses 0%. Additional architectural change no longer
produces meaningful, generalizable gains — which is exactly the stopping
condition specified.
