# RedactionBench validity audit — and a correction to two earlier claims

This is an independent validity pass on the benchmark, the metric, and the
upper-bound claims made in [`AUDIT.md`](AUDIT.md) / [`DIAGNOSIS.md`](DIAGNOSIS.md).
No implementation was changed. It reaches two conclusions that **correct** the
earlier documents, and confirms one strongly.

## TL;DR — what changed after reading the dataset's own definitions

1. **The "0.431 all-gold RChar ceiling" was a metric artifact and is retracted.**
   The dataset card defines `contextual` spans as *"may-redact-without-penalty …
   a privacy lower bound"* — redacting only the `mandatory` spans is an explicitly
   valid output. My harness's `all-gold` recall put **un-redacted contextual
   characters in the recall denominator**, penalizing exactly what the benchmark
   says carries no penalty. The recall-relevant quantity is **mandatory recall**,
   and the perfect-detector ceiling for it is **1.0, not 0.431**.
2. **"Contextual is mostly utility-destroying glue" was wrong.** Pure
   whitespace/punctuation ("combinators") is only **8.8% of contextual characters
   (5% of all gold)**. The majority is substantive gray-zone PII — IP addresses,
   user-agent strings, LDAP DNs, postal codes, dates, partial user-IDs, org names —
   which a good redactor legitimately *may* redact.
3. **Streaming is confirmed not the bottleneck**, now much more strongly (below).

Consequently the earlier "SafeStream is near its achievable ceiling" claim is **not
supported** and is withdrawn. There is real, legitimate recall headroom — it is
just concentrated in semantic PII (names/orgs), which needs NER, not regex.

## 1. Is the benchmark evaluator valid?

**The dataset is valid and carefully built; the *metric* I used is a proxy, not
the official R-Score.**

- Offsets are half-open `[start, end)` (card-confirmed) and my harness matches; 0
  offset violations across the corpus; non-ASCII (`Café`, `村上 健二`) aligns.
- Gold spans never overlap within a document → the necessity split is clean.
- Hand-verified metric test reproduces by-hand P/R/F1 exactly.
- **BUT: the official R-Score reference implementation is unreleased** (card: "A
  reference implementation will be released shortly"). My harness is a documented
  character-mask reimplementation. It differs from the official metric in at least
  two ways I can see from the card:
  - **Combinator normalization**: the official scorer groups composite entities so
    fine spans "don't dominate the metric". My char metric does not.
  - **Contextual treatment**: the card's "may-redact-without-penalty" means the
    official recall almost certainly does **not** penalize un-redacted contextual
    spans; my `all-gold` recall did.

  So absolute numbers from this harness are **directional proxies**, not official
  R-Scores, and must not be reported as R-Score in a paper.

**External anchor** (official R-Scores, from the card's leaderboard of 34 models):
best model `claude-opus-4-6` = **0.714**; `gpt-5.4` = 0.659; best GLiNER = 0.472;
DeBERTa-v3 PII models 0.25–0.46; rule/BIO baselines 0.20–0.34. **No system is near
1.0**, and the field is topped by frontier LLMs — evidence that this is an
NLU/contextual-reasoning task, and that near-1.0 is unreachable for anyone.

## 2. Is the 0.431 upper bound defensible?

**No — it is retracted.** Reproduced both readings on the corpus:

| Reading | perfect-mandatory result |
|---|--:|
| My `all-gold` RChar (contextual counted as required) | **0.431** ← artifact |
| Benchmark semantics (contextual = may-redact-without-penalty; recall over mandatory) | **mandatory recall = 1.000** |

`0.431 = mandatory_chars / (mandatory + contextual) = 165,239 / 383,462`. It is
arithmetically correct but semantically wrong: it treats optional spans as
required. Under the benchmark's own definition the recall ceiling is 1.0, and the
*achieved* recall figure that matters is **mandatory recall (0.691 core / 0.769
NER)**, not all-gold RChar (0.40).

## 3. Oracle by objective/semantic/ambiguous/glue (A/B/C/D), all gold

Every gold span classified by content; current SafeStream (core, no NER) coverage:

| Class | instances | chars | % of gold | current recall | achievable | how |
|---|--:|--:|--:|--:|--:|---|
| **A objective** (email, IP, SSN, card, tokens) | 1,513 | 55,861 | 14.6% | **0.732** | ~0.95 | already SafeStream's core; A-mandatory is 0.850 |
| **B semantic** (names, orgs, places) | 5,878 | 43,788 | 11.4% | **0.013** | ~0.6–0.8 | **NER only** — the big gap |
| **C ambiguous** (bare numbers, dates, partial IDs, codes, net-metadata) | 26,840 | 264,628 | 69.0% | 0.394 | ~0.5–0.7 (mandatory portion) | context/label anchoring; unlabeled stays ambiguous |
| **D glue** (whitespace/punctuation combinators) | 19,055 | 19,185 | 5.0% | 0.476 | n/a | incidental; normalized by official combinators |

Mandatory subset (the recall that matters): A=0.850, **B(names)=0.026**, C=0.726,
D≈0. The single dominant recoverable gap is **B (names): 16,004 mandatory chars at
0.026 recall** — recoverable only with NER, which is exactly why spaCy NER lifts
mandatory recall 0.691→0.769.

## 4. Contextual span inspection (utility of redacting them)

Composition of the 218,223 contextual characters: alnum-mixed 44.7%, alpha
word/phrase 21.4%, "other" 15.6%, digits 8.3%, **punctuation-glue 7.2% +
whitespace 1.6% = 8.8% pure glue**. Sampled examples with judgement:

| Example (contextual) | Redacting it is… |
|---|---|
| `Mozilla/5.0 (Windows NT 10.0…Chrome/122)` user-agent | **useful** (device/network metadata) |
| `cn=Leadership,ou=Groups,dc=bridgepointfin,dc=com` LDAP DN | **useful** (org structure) |
| `usr-8vLmKpTqN2xRzY` partial user id | **useful** |
| `192`,`.168`,`1.55` IP split into octets + `.` glue | **useful** (the IP), glue is incidental |
| `SANTA ANA, CA` / `P. O. Box` address fragments | **useful** (location) |
| `2019`, `16`, `3010` date/postal fragments | **ambiguous** (depends on policy) |
| standalone `.` `,` ` ` `@` `)` combinators | **unnecessary alone / natural in-entity** |

So the contextual class is mostly legitimate gray-zone PII, not noise. Blanket
redaction of standalone glue would be pointless, but redacting the *substantive*
contextual entities (IPs, addresses, orgs) is normal, in-scope, and **not
penalized** — a real, non-gaming path to a higher score.

## 5. Is streaming genuinely not the bottleneck? (validated hard)

Yes — the strongest possible evidence short of a proof:

- **1,392 deterministic adversarial cases, 0 failures**: six entity types at every
  offset across chunk boundaries (chunk 8/16/24/32); Unicode/CJK/emoji/combining
  marks straddling boundaries; multiple adjacent entities across one boundary; a
  token longer than the chunk at every offset; entities at the very head and tail.
- **NER adversarial: 0 mismatches** (names at chunk 32/64/256 vs whole).
- **Full-corpus streaming == whole**, byte-identical char metrics, including a run
  at **chunk-size 64** that forces heavy chunking on every one of the 200 docs
  (median length 6,410).
- Instrumented loss attribution: chunking/boundary 0.0%, offset mapping 0.0%,
  reconciliation 0.5%, final redaction 0.0%.

**Caveat (the one way it could break):** equivalence relies on the overlap window
being ≥ the longest entity plus the context a detector reads. At the default
overlap (8,192) this holds for every built-in tier and for spaCy NER at the chunk
sizes tested. A user who shrinks overlap below a detector's need would break it —
the engine already warns in that case. So the correct claim is *conditional*:
streaming is loss-free **given overlap ≥ detector requirements**, which the
default guarantees.

## 6. Architecture improvements — expected gain per dimension

Estimates are grounded in the A/B/C/D oracle. "Mand↑" = mandatory recall; "RChar↑"
= all-gold char recall proxy; ✓/– qualitative.

| Lever | Mand↑ | RChar↑ | Precision | Latency/Thru | Memory | Generalizes |
|---|--:|--:|---|---|---|---|
| **Stronger local NER (GLiNER/ONNX)** | **+0.05–0.10** | +0.03–0.06 | slight ↓ (name FPs) | ↓↓ (10–50×) | +100s MB | **high** (names universal) |
| Name gazetteer/dictionary (lightweight) | +0.02–0.05 | +0.01–0.03 | ↓ (common-word names) | ~neutral | +small | medium |
| Confidence calibration (existing `Calibrator`) | ~0 | ~0 | **↑** (trims entropy FP) | neutral | neutral | high |
| Rules∩NER ensemble agreement | ~0 | ~0 | ↑ | neutral | neutral | high |
| Context/label cascade (already added) | +0.005 | +0.002 | neutral | neutral | neutral | high |
| Better username/opaque-id handling | +0.01–0.03 | +0.01 | ↓↓ (risky) | neutral | neutral | low |
| Multilingual/accented NER | +0.01–0.02 | +0.01 | neutral | ↓ | + | high (non-EN) |
| Entity linking / disambiguation | ~0 recall | ~0 | ↑ | ↓ | + | medium |
| Adaptive windows / multi-pass / delayed finalization / voting / stateful streaming | **0** | **0** | – | ↓ | ↑ | n/a — targets 0%-loss stages |

The only lever with material recall headroom is **stronger NER** (class B is 0.013
today). Everything targeting the streaming/reconciliation path yields ~0, because
those stages are already loss-free.

## 7. Definitive answers

1. **Evaluator valid?** Dataset yes; my metric is a *proxy*, not official R-Score
   (unreleased; lacks combinator normalization; my all-gold recall over-penalized
   contextual). Trust **mandatory recall** as the proxy; do not call any number
   here "R-Score".
2. **0.431 defensible?** No — retracted; it is a denominator artifact from counting
   optional contextual spans as required. Benchmark-correct recall ceiling = 1.0.
3. **Streaming not the bottleneck?** Confirmed — 1,401 adversarial cases + full
   chunk-64 corpus equivalence, 0 divergences; conditional on overlap ≥ detector
   requirements (default guarantees it).
4. **Actual headroom?** Mandatory recall 0.69→~0.85 is achievable, dominated by
   **names (class B, 0.013→~0.7 with NER)**; the official-metric absolute is
   unknown until the scorer ships, but the leaderboard (0.42–0.71 for semantic
   systems) shows a regex+NER engine has real room. Near-1.0 is unreachable (best
   model 0.714).
5. **Worth implementing:** stronger local NER (biggest lever; use the existing
   `detectors/onnx_ner.py` tier with a GLiNER/ONNX model), optional lightweight
   name gazetteer, and confidence calibration for precision. All generalize.
6. **Do NOT implement:** adaptive windows, multi-pass, delayed finalization,
   candidate voting, stateful streaming (all target 0%-loss stages); blanket
   redaction of glue/contextual to inflate RChar; entropy down-tuning to this
   corpus (anti-generalization). None improve real quality.
7. **Safe paper claims:** (a) constant-memory streaming redaction whose output is
   **provably identical to whole-document** processing (boundary-loss-free) — the
   genuine architectural novelty; (b) strong recall on **objective** PII/credentials
   (A-mandatory 0.85) at constant memory; (c) names require the NER tier. Do **not**
   report an R-Score value pre-release, do **not** claim near-1.0, and report
   **mandatory** recall, not all-gold RChar.
8. **Experiments to add:** official R-Score once released; constant-memory scaling
   curve (Theorem 3, `scale_memory.py`); throughput vs compiled scanners;
   streaming-equivalence theorem + adversarial boundary matrix (novelty); A/B/C/D
   recall ablation; NER-model comparison (spaCy vs GLiNER vs ONNX); and a
   false-positive study on benign/public text (the card notes RB understates FP,
   since all its docs are private/semi-private).

## Corrections to prior documents

`AUDIT.md` and `DIAGNOSIS.md` should be read with these corrections: the **0.431
all-gold ceiling is withdrawn** (metric artifact), the **contextual-as-glue
characterization is wrong** (glue is 8.8% of contextual), and the **"near its
achievable ceiling" conclusion is not supported** — the recall-relevant metric is
mandatory recall (0.69/0.77) with real NER headroom, and no official-R-Score claim
can be made until the reference scorer is released.
