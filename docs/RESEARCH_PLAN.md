# Research Plan — Provably-Equivalent Streaming Redaction

Target: a top security/privacy journal (**IEEE Transactions on Dependable and Secure
Computing** or **Computers & Security**). This document is the execution plan for turning
SafeStream-Redactor from a well-engineered tool into a defensible research contribution.

The plan has three pillars, in dependency order:

1. **The theorem** — a formal output-equivalence guarantee under bounded memory and
   parallelism (the novelty).
2. **Real-corpus evaluation** — accuracy on independent labeled data, not the synthetic
   regression fixture.
3. **Baselines** — head-to-head comparison against the tools reviewers will expect.

---

## 1. Thesis and contribution

**One-sentence thesis.** *A PII-and-secret redactor that provably produces
whole-document-identical output under bounded memory and inter-process parallelism —
evaluated on independent clinical, NER, and real-secret corpora against Presidio
(NER-enabled), gitleaks, and an LLM baseline — matching or beating them on structured
PII and credentials while uniquely guaranteeing that sensitive text never leaves the
machine.*

**Novelty claim (the part that is new).** Existing redactors (Presidio, scrubadub) and
secret scanners (gitleaks, TruffleHog, detect-secrets) do not state, let alone prove, an
equivalence between their streaming/parallel execution and a whole-document reference
execution. SafeStream's chunked engine and parallel seam protocol admit such a proof.
The contribution is:

- **C1 — a formal model** of a multi-tier redaction pipeline as a function over text,
  with two explicit locality assumptions whose constants are measured from the
  implementation (Section 3).
- **C2 — three theorems**: streaming equivalence, parallel byte-identity (with a
  characterized, safe failure mode), and a constant-memory bound (Section 3).
- **C3 — an honest, reproducible evaluation** on independent corpora against real
  baselines, including a modern LLM redactor and a privacy-cost analysis of using one
  (Sections 4–5).

Engineering craft (overlap windows, prefiltering) is *supporting evidence*, not the
claim. The claim is the guarantee.

---

## 2. What is already true vs. what must be built

| Asset | State | Action |
| --- | --- | --- |
| Chunked streaming engine with overlap | Implemented (`engine.py`) | Formalize; prove Theorem 1 |
| Parallel seam protocol + fallback valve | Implemented (`parallel.py`) | Formalize; prove Theorem 2 |
| Constant-memory property | Implemented; one memory test | Prove Theorem 3; add scale curve |
| Detector locality (context bounds) | **Audited — see Section 3.3** | Write up; fix two exceptions |
| Synthetic benchmark | Implemented (`benchmarks/`) | Demote to regression fixture (already framed so) |
| Real-corpus evaluation | **Missing** | Build (Section 4) — the desk-reject risk |
| Baseline comparisons on real data | **Missing** | Build (Section 5) |
| Calibrated confidences | Hand-set constants | Train a calibrator (removes a reviewer objection) |

---

## 3. Pillar 1 — The formal model and theorems

### 3.1 Definitions

- Let `T` be the input text, a finite string over a character alphabet.
- A **detector** is a function `D : str -> P(Spans)`, where a span is a tuple
  `(i, j, type, conf)` with `0 <= i < j <= |T|`. `D(T)` is the whole-document reference
  output.
- The **pipeline** `Pi` composes the tiers, applies contextual scoring, filters by
  `min_confidence`, and resolves overlaps (`resolve_overlaps`) to a sorted,
  non-overlapping set. `Pi(T)` is the reference detection set.
- The **streaming engine** `S_w` (parameter: overlap `w`) consumes `T` as an arbitrary
  chunk sequence and emits `(segment, detections)` pairs. Let `S_w(T)` be the union of
  emitted detections, offsets mapped back to absolute positions in `T`.
- The **parallel engine** `P_{w,k}` splits `T` into `k` character-aligned ranges and
  redacts each with `S_w` extended by scanned pads and context prefixes, reconciled by
  the seam protocol.

### 3.2 Assumptions

- **A1 (bounded span length).** Every span in `Pi(T)` has length `j - i <= L_max`.
- **A2 (bounded context locality).** For any span `s = (i, j, ...)`, membership of `s`
  in `Pi(T)` and its final confidence depend only on the substring
  `T[i - C_left : j + C_right]`. That is, `Pi` is a sliding-window function with a
  left reach `C_left` and right reach `C_right`.

### 3.3 Audited constants (from the current implementation)

A trace of every detector's decision function yields:

- **`C_left = 48`.** The contextual scorer (`contextual.py`) reads a 48-char left window
  for boost/suppress; the label-anchored patterns (`AWS_SECRET`, `API_KEY`) fold their
  label into the match (~30 chars). Nothing reaches further left.
- **`C_right = 2`.** The widest right-context assertion is `(?!\.\d)` (phone / IPv4),
  reaching 2 characters. All other lookaheads/boundaries reach `<= 2`. Every validator
  (`luhn_ok`, `ssn_ok`, `ipv4_ok`, `ipv6_ok`, `phone_ok`) reads only the matched text —
  zero external reach.
- **`L_max`** is `< ~260` for every pattern **except two**:
  - `private_key`: PEM body bound `{1,8192}` yields spans up to ~8270 chars.
  - `secret` (entropy tier): candidate `{20,}` is **unbounded**.

**Implication.** A2 holds comfortably (`max(C_left, C_right) = 48 << w = 4096`). A1 holds
for all patterns *except* `private_key` and `secret`, which can exceed the default overlap
`w = 4096`. Theorem 1 requires `w >= max(L_max, C_left, C_right)`; the two long-span
patterns are therefore the exact and only cases where the default configuration does not
satisfy the premise.

**Work item WI-1 (correctness fix).** Choose one:
1. Set `DEFAULT_OVERLAP = 8192` and cap the entropy candidate to `{20,8192}`; or
2. Bound the private-key body and the entropy run to `w - marker_len`; or
3. State Theorem 1 conditionally and document these two as the only exceptions (the
   parallel seam valve already makes parallel mode safe for them via fallback).
Option 1 makes the guarantee unconditional at the default and is preferred. Note that the
parallel path is already safe for both (the seam valve falls back on disagreement); the
gap is only the sequential path.

### 3.4 Theorems (statements + proof obligations)

**Theorem 1 (Streaming equivalence).** *Under A1 and A2, if `w >= max(L_max, C_left,
C_right)`, then `S_w(T) = Pi(T)` for every `T` and every chunking of `T`.*

Proof obligations, each mapped to code:
- **(a) Completeness — every reference span is seen whole in some window.** The engine
  emits only text at least `w` from the buffer end, and retreats the emit boundary to a
  straddling detection's start (`engine.py`, boundary-retreat loop). With `w >= L_max`, a
  span cut by one boundary is carried whole into the next window.
- **(b) Soundness — no window produces a span absent from `Pi(T)`.** With `w >= C_left`,
  each window carries `w` chars of real left context (the `prefix`), and with the
  detection emitted `>= C_right` chars before the buffer's true continuation, all
  context assertions evaluate against real text, never an artificial boundary.
- **(c) Exactly-once emission.** The `ready` filter (`det.end <= emit_upto`) plus the
  disjoint carry region emit each span in precisely one segment.

**Theorem 2 (Parallel byte-identity, with safe fallback).** *Under A1 with
`w >= L_max`, `P_{w,k}(T) = S_w(T)` byte-for-byte. When A1 is violated at a seam, the
seam valve detects the disagreement and `P_{w,k}` falls back to `S_w`; thus
`P_{w,k}(T) = S_w(T)` unconditionally, and never silently diverges.*

Proof obligations: the straddler ownership rule (a seam-crossing span belongs to the left
worker), independent recomputation by both neighbours, and the valve's equality check
(`parallel.py`). The "unconditional equality via fallback" framing is the paper's
strongest single sentence — a guarantee competitors do not state.

**Theorem 3 (Constant-memory bound).** *Peak working memory of `S_w` is
`<= chunk_size + w + L_max`, independent of `|T|`; `P_{w,k}` uses `<= k` times that.*

Proof obligation: the buffer never retains more than `w` (plus one straddler) after each
emit. Substantiated empirically by the 100 GB scale curve (WI-6).

**Deliverable.** A `Formal Model` paper section: Definitions, A1/A2 with the audited
constants, Theorems 1–3 with proofs, and an explicit *limitations* subsection naming what
breaks the assumptions (a span longer than `w`; any future detector needing unbounded
right context, e.g. an LLM tier). Reviewers reward stating where a guarantee stops.

---

## 4. Pillar 2 — Real-corpus evaluation

Replace the synthetic generator as the accuracy source (keep it, explicitly, as a
regression fixture only).

### 4.1 Corpora

| Corpus | Covers | Access notes |
| --- | --- | --- |
| **n2c2 / i2b2 2014 de-identification** | Names, dates, IDs, locations (clinical) | Free DUA, ~1–2 wk approval. The de-id gold standard — **apply first** (long pole). |
| **CoNLL-2003** | PERSON / ORG / LOC (NER tier) | Public. |
| **Presidio research dataset** | Structured PII in templated text | Public (GitHub). |
| **SecretBench** (or mined GitHub-leak sets) | Real AWS/GitHub/JWT/keys in repos | Public labeled secrets — the credential-tier evidence. |
| Synthetic corpus (existing) | — | Regression fixture only; not an accuracy claim. |

### 4.2 Metrics

- Per-type and micro/macro **precision, recall, F1**.
- **95% confidence intervals** via bootstrap resampling.
- **Significance test** vs. each baseline (McNemar or paired bootstrap).
- **Error analysis**: categorize false negatives/positives per tool — often the section
  that gets a paper accepted.

### 4.3 Scale and ablation experiments (substantiate the theorems)

- **WI-6**: memory vs. file size to 100 GB — the flat line against the Theorem 3 bound.
- **WI-7**: throughput before/after an optional Vectorscan/re2 backend, with the
  byte-identity check empirically confirming Theorem 2.
- **WI-8**: parallel speedup vs. worker count + measured byte-identity across the corpus.
- **WI-9 (ablation)**: marginal F1 of each tier; **learned/calibrated confidence vs. the
  hand-set constants** (a small logistic calibrator trained on labeled data removes the
  "you just picked 0.5" objection permanently).

---

## 5. Pillar 3 — Baselines

Run each in its *strongest* configuration, through a common adapter in
`benchmarks/evaluate.py`, or reviewers will re-run them for you.

| Baseline | Class | Must-do |
| --- | --- | --- |
| **Microsoft Presidio** | PII | Enable the **NER tier** (spaCy/transformer), not just pattern recognizers. |
| **scrubadub** | PII | Standard reference. |
| **gitleaks** and/or **TruffleHog** | Secrets | The real competition for the credential claim — compare coverage *and* speed. |
| **Modern LLM redactor** | Both | Prompt a current model to extract PII+secrets; report P/R/F1, cost, latency, and that it **violates the offline guarantee** (data leaves the machine). This reframes SafeStream's slower throughput as a privacy/guarantee advantage. |

---

## 6. Threats to validity (pre-empt the reviewers)

- **Corpus representativeness** — clinical + templated + repo-mined secrets is broad but
  not exhaustive; state the gap.
- **Label mapping** — each corpus's tag set must be mapped to `EntityType`; publish the
  mapping and treat unmapped types as out-of-scope, not as errors.
- **Baseline fairness** — pin versions, configs, and prompts; release them.
- **Assumption violations** — the two long-span patterns (Section 3.3); resolve via WI-1
  and report both the fixed and conditional statements.

---

## 7. Timeline (roughly 4–8 months to submission)

| Phase | Weeks | Work |
| --- | --- | --- |
| 0 — De-risk | 1–2 | Apply for n2c2 DUA now; resolve WI-1 (correctness fix). |
| 1 — Formalize | 2–6 | Write the formal model + proofs of Theorems 1–3. |
| 2 — Harness | 2–6 (parallel) | Dataset + baseline adapters in `benchmarks/`. |
| 3 — Experiments | 6–12 | Accuracy, scale, ablations; train the confidence calibrator; optional Vectorscan backend. |
| 4 — Write-up | 12–20 | Error analysis, paper, artifact + (optional) public combined PII+secret benchmark release. |
| 5 — Submit | ~20 | IEEE TDSC or Computers & Security. |

---

## 8. Target venues

- **Primary (journal):** IEEE TDSC; Computers & Security (Elsevier). Both accept
  formal-guarantee + strong-evaluation systems-security work.
- **Stretch (top conference, security venues out-rank most journals):** USENIX Security,
  CCS, S&P, NDSS — would additionally require the public benchmark and a stronger
  novelty framing.
- **Artifact / dataset:** JOSS or SoftwareX for the software; a dedicated dataset paper
  if the combined PII+secret benchmark is released — a publishable contribution on its
  own.

---

## 9. Work-item checklist

- [ ] **WI-1** Resolve the two long-span exceptions so Theorem 1 holds unconditionally at
      the default overlap (or state it conditionally). *Correctness — do first.*
- [ ] **WI-2** Write the formal model: definitions, A1/A2, Theorems 1–3 with proofs.
- [ ] **WI-3** Apply for the n2c2 DUA.
- [ ] **WI-4** Build dataset adapters (n2c2, CoNLL, Presidio set, SecretBench).
- [ ] **WI-5** Build baseline adapters (Presidio NER-on, scrubadub, gitleaks, LLM).
- [ ] **WI-6** Memory-vs-size scale curve to 100 GB.
- [ ] **WI-7** Optional Vectorscan/re2 backend + byte-identity check.
- [ ] **WI-8** Parallel speedup + byte-identity across the corpus.
- [ ] **WI-9** Confidence calibrator + per-tier ablation.
- [ ] **WI-10** Error analysis and paper write-up; release artifact and benchmark.
