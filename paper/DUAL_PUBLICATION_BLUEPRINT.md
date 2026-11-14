# SafeStream-Redactor — Dual-Publication Blueprint

**Status:** plan only. No experiment in this document has been run unless it is marked
*measured*. Audited at commit `7275917` (main, 2026-11-14).

**Papers.**
- **Journal (J):** the existing IJIS manuscript, `paper/ijis/`. In this plan it is the
  `paper_journal/` you asked for. The folder is not renamed, because the manuscript's
  Data/Code-availability paths and commit hashes point to it.
- **Conference (C):** a new paper in `paper_conference/`, written from scratch. It
  reuses no text, figure, table or number from J.

---

## 0. Read this first: three gates only the authors can clear

The audit found three manuscripts that already overlap with J. Each one is a dual-submission
risk that either option below inherits, so they come first.

| # | Artefact | What overlaps with J | Measured text overlap | Required action |
|---|---|---|---|---|
| G1 | `paper/ftnct09/` (Springer CCIS, FTNCT'09) | Algorithm 1, the three theorems, constant memory, the tier cascade and the calibrator | 0.1% of J's 8-grams | **Find out its status.** If it was accepted or published, J is legally an *extension* of it. J's cover letter and introduction must then cite it and state the delta. Today the cover letter says "not under consideration elsewhere" and does not mention FTNCT'09. If it is still under review, J cannot go out until FTNCT'09 is decided or withdrawn. If it was never submitted, delete the folder from the submission story. |
| G2 | `paper/ieee-conference/` ("Character Recall Is Not Protection") | Same results as J: memory of 8.4–8.54 MiB from 8 MiB to 2 GiB, 41.1 MB/s on four workers, the boundary-safe engine, and the RedactionBench no-leak analysis (82.1% of documents leaking = J's 17.9% fully protected) | 1.4% of its 8-grams are in J | **Do not submit it.** Its headline is J's RQ5. Text overlap is low, but *result* overlap is what dual-submission policies (IEEE 8.2.4.F, Springer, COPE) judge. If it is already under review, withdraw it before J goes out. |
| G3 | `paper/journal/` (Computers & Security version) | It is J's predecessor | **48.7%** of its 8-grams are in J | Confirm it was never submitted, or was withdrawn. If it is under review anywhere, J cannot be submitted. |

> **Recommendation:** clear G1–G3 in writing (an e-mail among the authors is enough)
> before anything else. Everything below assumes G2 and G3 are shelved, and it handles
> both outcomes of G1.

How the overlap was measured: LaTeX source with commands and comments stripped,
lower-cased word tokens, and the share of one paper's distinct 8-word sequences that also
appear in the other. iThenticate works on similar n-gram matches.

---

## Deliverable 1 — Codebase-to-paper partition matrix

**Rule of the partition.** J owns *correctness and scale*: whether chunked or parallel
output can differ from a whole-document pass, and what the pattern cascade detects on
held-out data. C owns *what crosses an agent's tool boundary*: the neural tier, the
tool and transport surface, and the policy operators. These are evaluated on corpora and
with metrics that J never reports. **S** (shared) means the code is infrastructure that
both papers run; each paper describes it in at most one sentence and cites the other for
detail. **R** (reserve) means neither paper evaluates it, which keeps it free for a third
paper.

### 1.1 The five areas you asked about

| # | Area | Code | Owner | How the *other* paper frames it |
|---|---|---|---|---|
| 1 | Streaming equivalence; retreat out of straddling spans (Alg. 1, Thm 1); the tightness result that an overlap of max L_d can leak | `engine.py`, `detectors/base.py` (`StreamingRequirements`, `requirements_of`), `redactor.py` (`min_safe_overlap`) | **J** | C treats it as a black-box contract: "each tier declares (L, C_left, C_right) and the engine enforces the overlap [J]". C *tests* whether the ONNX tier's declaration (256/256/256) is honest. That is an empirical measurement, not a theorem. |
| 2 | Parallel seam protocol and fail-safe fallback (Thm 2); bounded buffer (Thm 3); Rust/PyO3 core and its parity with Python | `parallel.py`, `scheduler.py`, `memory_budget.py`, `native/src/*`, `native/tests/properties.rs` | **J** | C states the backend and worker count in its environment section only. C reports **no** memory or MB/s number for the pattern tiers, because those are J's figures. |
| 3 | Pattern cascade: regex + Luhn/E.164/SSN/IPv4/IPv6 validators, label-anchored identifiers, contextual scorer, entropy tier with benign-shape suppression, cross-tier union overlap resolution, opt-in dates and log-username tiers | `detectors/deterministic.py`, `labeled_id.py`, `contextual.py`, `entropy.py`, `structured.py`, `log_username.py`, `_lookaround_free.py`; resolver in `redactor.py` | **J** (RQ3–RQ7 and the ablation) | C freezes it as "Tier 0 at commit X" and describes it in one paragraph citing J. C reports **only deltas over Tier 0** (Tier 0 + neural minus Tier 0) on C's own corpora, never Tier 0's absolute accuracy as a contribution. |
| 4 | Regex-gated INT8 DistilBERT ONNX tier; spaCy NER | `detectors/onnx_ner.py` (gate `_candidate_windows`, `decode_bio`, `_snap_to_words`, `_join_spaced`, batching), `scripts/export_onnx.py`, `detectors/ner.py` | **C** for ONNX. spaCy is **S**: J evaluates it as SafeStream's NER tier on J's corpora; C runs it only as a *baseline* on C's corpora. | J must contain **no** ONNX result. Today J mentions DistilBERT once, in related work, which is fine. J may add one sentence: "an optional neural tier is evaluated separately [C]". |
| 5 | MCP server, REST API, SARIF, severity, policy operators (replace / mask / hash / HMAC pseudonymize / AES-GCM-SIV-style encrypt / fictionalize / fail-closed deanonymize), offline network guard | `mcp_server.py`, `api.py`, `sarif.py`, `severity.py`, `report.py`, `policy.py`, `operators.py`, `netguard.py`, `netguard_hard.py` | **C** | J keeps Definition 1, which lists the policies so that "redaction acts on each span separately" is defined. It reports no measurement of them. C cites J for *why* the operators must be pure functions of the span, so their equivalence across chunkings is J's, not C's. |

### 1.2 Every other module

| Code | Owner | Note |
|---|---|---|
| `detectors/gazetteer_ner.py`, `name_data.py` | **C** | Model-free name tier. It is the tier in which the audit found the MCP egress bug (§4.2). Its existing numbers (`benchmarks/redactionbench/SEMANTIC_DETECTION.md`) are on exposed RedactionBench, so C must re-measure on held-out data. |
| `detectors/semantic_ensemble.py`, `calibration.py` | **R** | FTNCT'09 already described the calibrator. Neither new paper needs them. |
| `detectors/regional.py`, `custom.py`, URL/IBAN rules | **R** / **S** | Not evaluated in J. Keep them out of C to keep its scope tight. |
| `detectors/registry.py`, `config.py`, `entities.py`, `errors.py`, `locate.py`, `_atomic.py`, `cli.py` | **S** | Infrastructure. Neither paper claims it as a contribution. |
| `watch.py` (fanotify/inotify DLP), `docs/FANOTIFY.md` | **R** | A natural third paper on kernel-level DLP enforcement. |
| `memstream/` | **R** | Unfinished and not distributed. |
| `ui/` | none | Demo only. |
| `benchmarks/chunking_leak.py`, `memory_curve.py`, `scale_memory.py`, `parallel_speedup.py`, `throughput*.py`, `native_backend.py`, `zero_copy_read.py`, `re2_backend.py` | **J** | `chunking_leak.py` gains an `--onnx` flag for C (§4.1 E4). C's runs go to separate result files. |
| `benchmarks/harness.py`, `corpora/`, `cluster_bootstrap.py` | **S** (tooling) | One scorer for both papers. *Corpora* are partitioned (below). |
| `benchmarks/scanner_sensitivity.py`, `leak_analysis.py`, `paired_from_checkpoints.py`, `tab_score.py`, `eval_log_usernames.py`, `loghub_agreement.py`, `redactionbench/*` | **J** | `tab_score.py` is reused by C on a *different* TAB split. |
| `benchmarks/tiered_bench.py` | **C** | It already measures Tier 0 vs Tier 0 + gated ONNX. |
| `benchmarks/realworld/` | **R** | J's "evaluation plan for real-world evidence". |
| `evaluate.py`, `presidio_compare.py`, `compare.py`, `baseline.py`, `summarize.py`, `calibrate.py` | legacy | Superseded by `harness.py`. Neither paper uses them. |
| Tests: `test_streaming_*`, `test_boundary_adversarial`, `test_parallel`, `test_scheduler`, `test_memory*`, `test_native_backend`, `test_kernel_hardening`, `test_fail_closed_overlap`, `test_detectors`, `test_labeled_id`, `test_checksum_ids`, `test_log_username`, `test_tab_score` | **J** | Cited as J's verification evidence. |
| Tests: `test_mcp`, `test_onnx_mock_pipeline`, `test_recall_vectors` (gate cases), `test_redaction` (operator cases), `test_netguard_hard`, `test_gazetteer_ner` | **C** | Plus the new tests listed in §5.2. |

### 1.3 Corpus partition (the main guard against overlapping results)

| Corpus | J | C |
|---|---|---|
| presidio-research test, secrets (Nosey Parker) test, RedactionBench, Loghub OpenSSH/Linux, TAB **test** (127 judgments), generated logs | ✔ | ✘ do not report |
| **ai4privacy** test half (3,973 docs; manifest exists; the dev half was used for tuning) | ✘ | ✔ main synthetic PII corpus |
| **CoNLL-2003** test half (173 docs) | ✘ | ✔ in-distribution upper bound only: the DistilBERT checkpoint was trained on CoNLL train |
| **TAB official dev split** (`echr_dev.json`; judgments disjoint from J's test split) | ✘ | ✔ real text with human gold. Needs a new loader and a manifest frozen before scoring. |
| `benchmarks/data/benign/` (benign prose) | ✘ | ✔ false alarms on public prose |
| Loghub systems **not** used in J (pick from Apache, HDFS, Zookeeper, Spark, …) | ✘ | ✔ gate pass rate on machine text only (no gold) |
| **AgentTrace** (new, synthetic agent tool outputs with planted values) | ✘ | ✔ plumbing only: egress and latency, **never** a detection-accuracy claim, because the planted formats come from the same authors as the rules |

---

## Deliverable 2 — Two publication options

### Option 1 — Simultaneous, orthogonal split ✅ recommended

- **J (IJIS, submit now):** *correctness and scale of chunked redaction.* The overlap
  condition, its tightness, the three theorems, the chunking-leak measurement, memory and
  throughput, and the held-out, cluster-robust evaluation of the pattern cascade. That is
  the current draft, trimmed (§5.1).
- **C (conference, submit after about 3–4 weeks of experiments):** *what an LLM agent
  learns through a redaction tool.* The regex-gated on-device neural tier (accuracy,
  latency, gate efficacy, determinism under INT8 batching, honesty of its declared
  context), the MCP/REST/SARIF egress contract (including the metadata leak the audit
  found), and the cost of each policy operator per tool call.

**Firewall rules** (check every one before submitting C):
1. No number in C may appear in J, and the reverse. `paper_conference/check_disjoint.py`
   enforces this automatically (§5.2 step 9).
2. No shared figure or table, and no architecture figure redrawn from J's
   `fig_architecture`. C draws the agent ↔ guardrail topology instead.
3. Shared 8-grams below 2% between the two `.tex` files (same script).
4. C's corpora are disjoint from J's (§1.3).
5. Each paper cites the other once, in the place given in the Deliverable 3 boundary
   statements. Both cover letters name the other manuscript as related work under
   review, and the authors offer it to the editor.
6. C's threat model is different: an online agent loop and a curious or compromised
   model reading tool outputs. J's is an offline shared artefact read later.

**Why this option is faster:** J is ready now; only the trimming and the G1 disclosure
remain. C needs no change to J. The two review clocks run in parallel.
**Why it is safe:** the papers answer different questions on different data. Salami
slicing means splitting one study into the smallest publishable units; here neither
paper's results are needed to evaluate the other's claims.
**Main risk:** a reviewer who sees both may say "same system, two papers". Rules 5 and 6
are the mitigation: say plainly that it is one system and two research questions.

### Option 2 — Conference first, then a journal extension of at least 35%

- **C2 (conference):** the overlap condition and its tightness (Thm 1), Algorithm 1, and
  the chunking-leak measurement (J's RQ1 and RQ2, about 8 pages).
- **J2 (journal, after C2 is accepted):** C2 plus the parallel seam protocol and Thm 2
  with proof, Thm 3, Rust parity, the whole detection evaluation (RQ3–RQ7: six corpora,
  three Presidio configurations, gitleaks and TruffleHog, cluster and two-stage
  bootstrap, scanner sensitivity, contamination analysis, the log-username tier, TAB) and
  the ablation. That is well over 50% new material, so the 35% threshold is easily met.
- **Cost:** J cannot be submitted until C2 is accepted. Many editors also want the
  conference version published first. That adds one conference review cycle (typically
  3–6 months) to a manuscript that is ready today. The ONNX/MCP work would still need a
  home, which is Option 1's C anyway.

**If G1 shows FTNCT'09 was accepted, Option 2 has already happened:** FTNCT'09 is the
conference paper and J is its extension. J's extension delta over FTNCT'09 (held-out
splits, six corpora, scanners, the tightness result, chunking-leak measurement, real logs,
TAB, the cluster bootstrap) is large, but it must be *stated* in J's cover letter and
introduction. The new conference paper is then Option 1's C, unchanged.

### Verdict

**Option 1 is both faster and safer** in either outcome of G1. Submit J as soon as G1–G3
are cleared and the trim is done. Run C's experiments in parallel and submit C to the
next suitable call for papers.

Venue shortlist for C (check each call's page limit, blind policy and dates yourself; I
have not verified them):
- **IEEE SecDev:** DevSecOps and agent tooling fit, IEEE format.
- **Springer ICISS (LNCS):** a strong regional fit.
- **DPM @ ESORICS (LNCS):** privacy engineering.
- **ACM AISec @ CCS:** an ML/security fit, but ACM format.

If a venue is double-blind, mirror the repository through an anonymiser such as
anonymous.4open.science and cite J in the third person.

---

## Deliverable 3 — Titles, abstracts, research questions, novelty boundary

Lexical overlap (Jaccard on content words, stop-words removed), *measured* for every
J × C title pair: the maximum is 4.8%. The only shared words are "free" (J2/C3) and
"context" (J3/C3).

### Paper 1 — Journal (IJIS)

**Titles**
1. *Bounded-Memory Streaming Redaction of Personal Data and Credentials with a
   Whole-Document Equivalence Guarantee* (current)
2. *How Much Overlap Is Enough? Detector-Declared Locality Bounds for Leak-Free Chunked
   and Parallel Redaction*
3. *Chunking Without Leaking: Provable Whole-Document Equivalence for Context-Dependent
   Streaming Redaction*

**Abstract:** keep the current one (`paper/ijis/main.tex:65`). It contains no
ONNX, MCP or policy claim. If G1 says FTNCT'09 was published, add one clause naming it
as the earlier conference version.

**Research questions.** J currently has seven (RQ1–RQ7). Group them into four for
the introduction and keep the seven section numbers as sub-questions, so that no result
moves.

| RQ | Hypothesis | Independent variables | Dependent variables and metrics | Data and baselines | Evidence in repo |
|---|---|---|---|---|---|
| **J-RQ1** Is the overlap condition necessary and sufficient in practice? (now RQ1) | H1a: naive and overlapping-window chunking miss reference detections on every corpus at c ≤ 4 KiB. H1b: with w ≥ w⋆, SafeStream's detection set equals the whole-document set under every chunking tried. H1c: w = max L_d admits a counterexample. | strategy {naive, overlapping o ∈ {256, 1024, 8192}, SafeStream}; chunk size c ∈ {1, 4, 16, 64} KiB; 5 random chunkings | missed reference detections; leaked gold spans; runs identical to reference / runs tried | secrets, presidio-research, RedactionBench, Loghub, generated logs, TAB test; baseline = whole-document pass of the same pipeline | `benchmarks/chunking_leak.py`; `tests/test_streaming_contract.py`, `test_streaming_requirements.py`, `test_boundary_adversarial.py`, `test_fail_closed_overlap.py`; `research/results/raw/2026-11-1{2,3}_chunking_leak_*.json` |
| **J-RQ2** Are parallel and native outputs identical to the sequential reference, and how often does the seam check fall back? (part of RQ1) | H2: byte identity on all inputs; fallback rate 0 under w ≥ w⋆ | workers k ∈ {1, 2, 4}; backend {Python, Rust}; input size | byte equality; number of fallbacks | generated and corpus files; baseline = sequential Python | `benchmarks/parallel_speedup.py`, `native_backend.py`; `tests/test_parallel.py`, `test_native_backend.py`, `native/tests/properties.rs`; `research/results/diagnostics/2026-10-11_*` |
| **J-RQ3** Is working memory independent of input size, and how does throughput scale? (now RQ2) | H3: peak RSS of streaming `redact_file` stays flat from 8 MiB to 2 GiB; whole-document `redact()` grows linearly | input size (8 MiB–2 GiB); API {stream, whole}; backend; workers | net peak RSS (MiB); MB/s, mean of 5 runs | generated logs; baseline = whole-document redaction | `benchmarks/memory_curve.py`, `scale_memory.py`, `throughput_repeat.py`; `tests/test_memory*.py`; `research/results/raw/2026-10-11_memory_curve_*.jsonl` |
| **J-RQ4** How well does the cascade detect credentials and personal data on held-out and real data, and which margins survive dependence-aware resampling? (now RQ3–RQ7 plus ablation) | H4a: fully redacted credential rate > gitleaks and > TruffleHog (paired CI excludes 0 under document, cluster and two-stage resampling). H4b: on human-annotated real prose, no margin over Presidio is assumed (two-sided). | system {SafeStream pattern / +dates / +spaCy; Presidio regex / sm / lg; gitleaks; TruffleHog (default and filters off)}; resampling scheme | char P/R/F1; fully redacted rate; false-alarm document rate; mandatory recall; no-leak document rate; TAB entity recall; paired median differences with 95% CI | the J corpora in §1.3 | `benchmarks/harness.py`, `cluster_bootstrap.py`, `scanner_sensitivity.py`, `tab_score.py`, `eval_log_usernames.py`, `leak_analysis.py`; checkpoints in `research/results/raw/2026-11-1*_checkpoints*/` |

No new J experiment is needed.

### Paper 2 — Conference

**Titles**
1. *Nothing Crosses the Tool Boundary: Auditing an On-Device MCP Guardrail for Secrets
   and PII in LLM Agent Workflows*
2. *Gate Before You Infer: Regex-Triaged On-Device Neural NER as a Privacy Guardrail for
   AI Coding Agents*
3. *Content-Free by Contract? Metadata Egress, Latency and Neural Recall of a Model
   Context Protocol Sanitizer*

**Draft abstract** (placeholders in ⟨⟩ are filled only from measured results):
> LLM coding agents read logs, configuration files and stack traces through tools, and
> whatever a tool returns enters the model's context. Agents are now being given redaction
> tools through the Model Context Protocol (MCP). We ask what such a tool lets the agent
> learn. We study an on-device guardrail that combines a frozen pattern cascade with an
> INT8 DistilBERT tagger, which a regular-expression gate invokes only on short windows
> around name-shaped candidates. On ⟨held-out corpora⟩ the gated tier raised person-name
> recall by ⟨Δ⟩ over the pattern cascade, at ⟨x⟩ ms per KiB, and sent only ⟨p⟩% of
> characters to the model. The gate itself missed ⟨g⟩% of gold names. Batched INT8
> inference made output depend on chunking in ⟨n⟩ of ⟨N⟩ runs. A differential audit of
> every tool response found that a "content-free" explanation tool returned normalised
> personal names through detector metadata. We fix it with an allow-list and verify zero
> egress across ⟨M⟩ calls. Per-call latency over stdio was ⟨…⟩, and keyed pseudonymisation
> and encryption cost ⟨…⟩ over plain replacement.

**Research questions**

| RQ | Hypothesis (decision rule: paired 95% bootstrap CI excludes 0, 2,000 resamples, seed 0, `harness.py`) | Independent variables | Dependent variables and metrics | Data and baselines | Script |
|---|---|---|---|---|---|
| **C-RQ1** Does the gated neural tier improve name, organisation and location detection over the frozen cascade, and how does it compare with statistical NER, at what latency? | H1a: Tier 0 + ONNX-gated > Tier 0 on PERSON char recall (ai4privacy test, TAB dev). H1b: ONNX-gated has ≥ spaCy-sm's PERSON F1 at lower per-KiB latency. H1c: the false-alarm rate on benign prose does not rise significantly. | NER component {none, ONNX-gated, ONNX-ungated, spaCy-sm, spaCy-lg}; baselines {Presidio-sm, Presidio-lg, optionally Presidio-trf}; batch size {1, 32} | per-type char P/R/F1; covered entity recall; TAB entity recall; benign false-alarm rate; p50/p99 latency per document; MB/s; load time; peak RSS | ai4privacy test, CoNLL test (upper bound), TAB dev, benign set | `benchmarks/harness.py` (systems `safestream-native`, `-onnx`, `-onnx-batched`, `-spacy`, `presidio-*` exist). **New:** system `safestream-native-onnx-ungated`, defined in the benchmark only by replacing `_candidate_windows` with whole-line windows (no product change). **New:** `load_tab_dev` loader. `tab_score.py` (reused). `tiered_bench.py` (mixed log stream). |
| **C-RQ2** How good and how cheap is the gate, and is the neural tier deterministic and honest about its context under streaming? | H2a: gate recall (share of gold names inside some candidate window) is well above the ONNX-ungated recall gap, so the gate costs little recall. H2b: on machine logs the gate sends under ⟨p⟩% of characters to the model. H2c: with batch size 1, streamed output equals whole-document output; with batch 32 (INT8 dynamic quantisation) it does not. H2d: no decision depends on context beyond the declared 256 characters. Probe it adversarially with chained title-case candidates, whose merged windows can grow along one line. | corpus; gate {on, off}; batch {1, 32}; chunk size; context truncation k ∈ {0, 8, 16, 32, 64, 128, 256, 512} | gate recall; gate pass rate (characters and windows); triage bypass rate = gold names outside every window; divergence count vs whole-document; label flip rate vs k; maximum observed effective context | same as C-RQ1, plus Loghub systems not used in J | **New:** `benchmarks/gate_audit.py` (needs no model). **New flags:** `chunking_leak.py --onnx --onnx-batch N`. **New:** `benchmarks/context_sensitivity.py`. |
| **C-RQ3** Does any value an agent should not see reach it through the tool surface? | H3a: before the fix, `explain_detection` leaks normalised names through `notes.norm` (the audit already confirmed this, §4.2). H3b: after an allow-list fix, no `scan` / `explain_detection` / REST `/scan` / SARIF output contains any gold value in raw, case-folded, whitespace-normalised, base64 or hex form, over all tier configurations. H3c: `redact` output leaks exactly the values the detectors miss, so residual exposure equals 1 − covered recall. Report that and stop there. | tool {scan, redact, explain_detection, detectors, health, REST /scan and /redact, SARIF}; tier set {pattern, +gazetteer, +ONNX, +spaCy}; commit {pre-fix, post-fix}; encoding of the probe | egress rate per tool and per JSON key path; residual exposure per corpus and per mode; bits disclosed by offsets, lengths and mask mode (analytic table) | TAB dev, ai4privacy test, AgentTrace | **New:** `benchmarks/mcp_egress_audit.py` (differential: plant → call → search). **New:** `tests/test_mcp_egress.py` (property test, fails on any egress). **New:** `benchmarks/generate_agent_traces.py`. |
| **C-RQ4** What does the guardrail cost per agent tool call, by transport, payload and policy mode? | H4a: in-process and stdio latency are both dominated by detection, not JSON-RPC framing, for payloads ≥ ⟨s⟩ KiB. H4b: hash, HMAC pseudonymise and fictionalise add < ⟨r⟩% to replace on end-to-end redaction; AES-GCM encrypt adds the most. H4c: encrypt → deanonymize round-trips exactly, and a tampered token is never restored (fails closed). | transport {in-process `handle()`, stdio via the `mcp` SDK client (installed: 2.3.0), REST}; payload 256 B–4 MiB; tier set; mode {replace, mask, hash (salted), pseudonymize, encrypt, fictionalize} | p50/p95/p99 latency; calls/s; cold-start (initialize) time; policy rendering µs per detection; end-to-end MB/s per mode; output inflation (bytes out / bytes in); round-trip exactness; wrong restorations under bit flips; SARIF 2.1.0 schema validity; ms per 1,000 findings | AgentTrace; one generated file per payload size | **New:** `benchmarks/mcp_latency.py`, `benchmarks/policy_overhead.py`. SARIF validation goes in `policy_overhead.py --sarif` (schema fetched from the OASIS GitHub repository, which is reachable). |

### Novelty boundary statements

**In J (one paragraph in the introduction or related work):**
> SafeStream also ships an optional on-device neural tier and an agent-facing tool
> interface; their detection quality, metadata egress and per-call cost are evaluated in
> a separate study [C] and are outside the scope of this paper. Every result here comes
> from the pattern tiers and, where stated, the spaCy tier. None depends on the neural
> tier or the tool interface. The neural tier's declared context is covered by the
> overlap condition of Section 5, but its accuracy and determinism are not claimed here.

**In C (one paragraph in Section 3):**
> The pattern cascade we use as Tier 0, and the streaming engine whose overlap rule makes
> chunked output equal to whole-document output, are analysed and evaluated in [J]. We
> treat both as a frozen substrate at commit ⟨hash⟩ and report none of their results.
> This paper's contributions are the gated neural tier, the audit of what crosses the
> tool boundary, and the per-call cost. They are measured on corpora [J] does not use,
> and every Tier 0 number here appears only as the baseline of a paired difference.

---

## Deliverable 4 — Experiments and code tasks for C

### 4.1 Experiments

| ID | Experiment | Answers | Runnable here now? |
|---|---|---|---|
| E1 | Gate audit: gate recall, pass rate and triage bypass rate per corpus and per entity type. Logs vs prose. | C-RQ2 | **Yes** on TAB dev and Loghub (from GitHub). ai4privacy and CoNLL are blocked (see 4.3). |
| E2 | Accuracy grid: Tier 0 / +ONNX-gated / +ONNX-ungated / +spaCy-sm/lg / Presidio-sm/lg, with paired CIs | C-RQ1 | Blocked: model, ai4privacy and CoNLL need `huggingface.co`. spaCy models (GitHub releases) and Presidio (PyPI) can be installed. |
| E3 | Cost per system: p50/p99 per document, MB/s, load time, RSS (from the harness), plus `tiered_bench.py` on a mixed log stream | C-RQ1 | Blocked on the model; Tier 0 part runs now. |
| E4 | Determinism: `chunking_leak.py --onnx` at batch 1 and 32, chunk sizes 1–64 KiB, 5 seeds | C-RQ2 | Blocked on the model. A mock-model dry run is possible now. |
| E5 | Context sensitivity: truncate left/right context to k, measure flip rate; adversarial chained-candidate lines | C-RQ2 | Blocked on the model. |
| E6 | Egress audit, pre-fix and post-fix, all tools × tier sets × probe encodings | C-RQ3 | **Yes** for pattern and gazetteer tiers. ONNX/spaCy rows wait for the model. |
| E7 | Residual exposure through `redact` per mode on AgentTrace, plus the analytic side-channel table (lengths, offsets, mask keep-last-4) | C-RQ3 | **Yes** |
| E8 | MCP and REST latency: in-process, stdio with the `mcp` SDK client, HTTP; 1,000 calls per cell | C-RQ4 | **Yes** (pattern and gazetteer); ONNX rows later |
| E9 | Policy overhead and round-trip: six modes; deanonymize exactness; 10,000 tampered tokens | C-RQ4 | **Yes** (`cryptography` 50.0.1 is installed) |
| E10 | SARIF schema validity and generation cost | C-RQ4 | **Yes** |

Rule for honest ordering: run **E6 on the pre-fix commit first** and save its JSON.
Then fix the leak, then re-run. The pre-fix commit (`7275917`) is public, so anyone can
reproduce the "before" number.

### 4.2 The egress bug the audit found (*measured*)

```bash
PYTHONPATH=src python - <<'EOF'
from safestream_redactor.redactor import Redactor
from safestream_redactor.mcp_server import MCPServer
s = MCPServer(Redactor(use_gazetteer=True))
r = s.handle({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain_detection",
  "arguments":{"text":"Patient: Dr. Maria Gonzalez was seen today."}}})
print(r["result"]["structuredContent"]["explanations"][0]["notes"])
EOF
# -> {'signal': 'honorific', 'norm': 'maria gonzalez'}
```

- **Cause:** `_tool_explain` (`src/safestream_redactor/mcp_server.py:247`) returns *every*
  `det.meta` key except `context`, and `gazetteer_ner.py:256` puts the case-folded name
  in `meta["norm"]`.
- **Why it matters:** this contradicts `docs/MCP.md` ("no secret text"). The existing test
  `test_explain_never_returns_the_secret` passes only because it uses tiers whose metadata
  carries no value.
- **Fix (after E6-pre):** return an allow-list of metadata keys, for example
  `signal, entropy, shape, cue, field, spacy_label, onnx_label, onnx_score, model, policy, score, evidence`,
  instead of a deny-list.
- **Check whether the allow-list is enough:** `labeled_id`'s `cue` and `structured`'s
  `field` are labels, not values. Confirm with E6 before trusting the allow-list.
- **SARIF and REST `/scan`** are content-free by construction: `sarif.Finding` has no
  metadata field, and `/scan` returns offsets and types only.

### 4.3 Environment blockers in this container (checked)

| Need | Status | Fix |
|---|---|---|
| DistilBERT checkpoint (`dslim/distilbert-NER`), ai4privacy, CoNLL | `huggingface.co` is refused by the proxy (403) | Allow `huggingface.co` and its file CDN hosts in the environment. Alternatively, run `scripts/export_onnx.py` on a laptop and attach `model.int8.onnx`, `tokenizer.json` and `labels.json` (with SHA-256) as a GitHub release asset. Do not commit them to git. |
| TAB, Loghub, spaCy models, SARIF schema | GitHub is reachable | none |
| Presidio, `tokenizers`, `maturin` | PyPI is reachable | `pip install` |
| Rust core (`safestream_native`) | `cargo` is present, the module is not built | `pip install maturin && maturin develop -m native/Cargo.toml --release` |
| spaCy, Presidio, gitleaks | not installed | gitleaks is not needed by C |

---

## Deliverable 5 — Outlines and execution checklist

### 5.1 Outlines

#### Conference (IEEEtran, 8 pages plus references; about 6,500 words)

For Springer LNCS (about 16 pages), double the page budget per section.

| § | Section | Pages | Words | Content | Figures / tables |
|---|---|---|---|---|---|
| 1 | Introduction | 0.9 | 800 | Agents read tool output; MCP redaction tools are proliferating; the question "what does the agent learn?"; three contributions | — |
| 2 | Threat model and background | 0.7 | 600 | A curious or compromised model and a prompt-injected agent; the tool boundary as an egress channel; MCP, JSON-RPC; why on-device; non-goals | **Fig. 1** agent ↔ MCP guardrail ↔ workspace topology with the trust boundary (new; not J's architecture) |
| 3 | System | 1.4 | 1,200 | Tier 0 in one paragraph (cite J); the gate (two triggers, 32-character context, recasing); INT8 DistilBERT, batching and why INT8 breaks determinism; tool surface and content-free contract; operators as pure functions (cite J for why) | **Alg. 1** gate and window merge; **Table I** tool contract (tool → fields returned → content-free by construction or by test) |
| 4 | Methodology | 0.9 | 750 | Corpora (§1.3 C column, frozen manifests); systems; metrics; protocol committed before runs; environment | **Table II** corpora |
| 5 | Results | 3.0 | 2,500 | C-RQ1 accuracy and latency; C-RQ2 gate and determinism; C-RQ3 egress before and after; C-RQ4 cost | **Table III** accuracy with paired CIs; **Fig. 2** recall-vs-latency Pareto; **Fig. 3** gate recall vs pass rate (prose vs logs); **Table IV** egress matrix pre/post fix; **Fig. 4** latency CDF by transport; **Table V** policy overhead and round-trip |
| 6 | Discussion and limitations | 0.5 | 450 | No real agent runs; AgentTrace is synthetic; CoNLL is in-distribution; length side-channel remains; single model | — |
| 7 | Related work | 0.5 | 400 | De-identification NER; LLM privacy guardrails; tool and agent security; secret scanners. Cite J once. | — |
| 8 | Conclusion | 0.1 | 100 | — | — |

That is 4 figures, 5 tables and 1 algorithm, all new.

#### Journal (Springer `sn-jnl`, IJIS; target 22 pages plus Online Resource 1)

The current draft is about 31 pages. Trim it as follows; no result changes.

| § | Section | Target pages | Change |
|---|---|---|---|
| 1 | Introduction | 2.0 | Group RQ1–RQ7 under J-RQ1 to J-RQ4. Add the J novelty-boundary paragraph. Add the FTNCT'09 disclosure if G1 requires it. |
| 2 | Background and related work | 1.5 | Unchanged |
| 3 | Problem statement and threat model | 1.0 | Unchanged |
| 4 | Design (tiers, overlap resolution, Alg. 1, window figure, parallel, implementation) | 3.0 | Fig. 1 (architecture) and Fig. 2 (window) |
| 5 | Formal analysis (A1, A2, Eq. 1, Thms 1–3, derived vs assumed) | 2.5 | Table 1 bounds |
| 6 | Methodology | 2.0 | Table 2 corpora |
| 7 | Results: RQ1 (Table 3 chunking), RQ2 (Fig. 3 memory), RQ3–RQ5 (Tables 4–6), RQ6/RQ7 (Tables 7–9), ablation | 7.0 | **Move:** Table 8 (Linux user-name tier) and the user-name narrative to Online Resource 1, keeping 3 sentences. Merge Tables 7 and 8 into one "real logs" table. Shorten the §RQ5 prose by about 30%. |
| 8 | Discussion and threats | 1.5 | Shorten the evaluation-plan subsection to one paragraph |
| 9 | Conclusion | 0.3 | Unchanged |
| — | Declarations, appendix proofs | 1.5 | Unchanged |

### 5.2 Execution checklist for C (what I will run next, in order)

Each step is a separate commit on `claude/safestream-dual-publication-blueprint-9hs5p3`.
Nothing in `paper/ijis/` changes except the one boundary paragraph, which waits for your
approval.

**1. Gate 0.** You answer G1–G3. I do nothing to J until then.

**2. Set up the environment.**

```bash
pip install -e '.[dev,onnx,ner,bench,crypto]' maturin
```

```bash
maturin develop -m native/Cargo.toml --release
```

```bash
python -m spacy download en_core_web_sm
```

```bash
python -m spacy download en_core_web_lg
```

Then get the model: allow `huggingface.co` and run the export below, or place the
release asset in `models/ner/`.

```bash
python scripts/export_onnx.py --out models/ner
```

```bash
sha256sum models/ner/* > paper_conference/MODEL_SHA256.txt
```

**3. Data.**

```bash
git clone https://github.com/NorskRegnesentral/text-anonymization-benchmark /tmp/tab
```

Copy `echr_dev.json`, the licence, the README and `REVISION` into
`benchmarks/data/external/tab_dev/`. Fetch ai4privacy and CoNLL as described in
`benchmarks/corpora/README.md` once Hugging Face is reachable.

**4. Write the protocol before any run.** Create `paper_conference/PROTOCOL.md` with the
RQs, hypotheses, systems, metrics, planned comparisons and the gate/threshold freeze
commit. Add `load_tab_dev` and freeze its manifest:

```bash
python -m benchmarks.corpora.split tab_dev
```

Commit both. This mirrors the TAB practice in J (commit `17b80c4`).

**5. Benchmark code**, each with one small test:
- `gate_audit.py`
- `mcp_egress_audit.py` + `tests/test_mcp_egress.py`
- `generate_agent_traces.py`
- `mcp_latency.py`
- `policy_overhead.py`
- `context_sensitivity.py`
- `chunking_leak.py --onnx/--onnx-batch`
- harness system `safestream-native-onnx-ungated`

**6. Run E6 on the pre-fix commit and save it.**

```bash
python -m benchmarks.mcp_egress_audit --corpus tab_dev --corpus agent_traces --tiers pattern gazetteer --json research/results/raw/conf/E6_egress_prefix.json
```

**7. Fix the egress bug** (allow-list in `mcp_server.py`, test first). Re-run E6 to
`E6_egress_postfix.json`.

**8. Run the rest** (outputs go to `research/results/raw/conf/`; J's files are never
touched):

```bash
python -m benchmarks.gate_audit --corpus tab_dev ai4privacy conll2003 loghub --json research/results/raw/conf/E1_gate.json
```

```bash
python -m benchmarks.harness --corpus ai4privacy --split test --systems safestream-native safestream-native-onnx safestream-native-onnx-ungated safestream-native-onnx-batched safestream-native-spacy presidio-sm presidio-lg --checkpoint-dir research/results/raw/conf/ckpt_ai4privacy --json research/results/raw/conf/E2_ai4privacy.json
```

Repeat that command with `--corpus conll2003` and `--corpus tab_dev`; then score TAB dev:

```bash
python -m benchmarks.tab_score --system onnx=research/results/raw/conf/ckpt_tab_dev/... --json research/results/raw/conf/E2_tab_dev_score.json
```

```bash
python benchmarks/tiered_bench.py --model models/ner --workers 1 4 --json research/results/raw/conf/E3_tiered.json
```

```bash
python -m benchmarks.chunking_leak --corpus tab_dev --onnx --onnx-batch 1 --json research/results/raw/conf/E4_det_b1.json
```

Repeat the last command with `--onnx-batch 32`, then:

```bash
python -m benchmarks.context_sensitivity --corpus tab_dev --json research/results/raw/conf/E5_context.json
```

```bash
python -m benchmarks.mcp_latency --transports inproc stdio rest --sizes 256 4096 65536 1048576 4194304 --calls 1000 --json research/results/raw/conf/E8_latency.json
```

```bash
python -m benchmarks.policy_overhead --modes replace mask hash pseudonymize encrypt fictionalize --tamper 10000 --sarif --json research/results/raw/conf/E9_policy.json
```

**9. Figures, tables and the disjointness guard.**
- `paper_conference/make_figures.py` reads only `research/results/raw/conf/`.
- `paper_conference/check_disjoint.py` fails if any number with 3 or more significant
  digits appears in both `paper_conference/main.tex` and `paper/ijis/main.tex`, or if
  more than 2% of 8-grams are shared.

**10. Draft** `paper_conference/main.tex` (IEEEtran; written from scratch, no text copied
from `paper/ieee-conference/`), `refs.bib` and `README.md` with build steps and the
number-to-file map. Build it:

```bash
cd paper_conference && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

**11. Verify:** `pytest -q`, `check_disjoint.py`, and re-derive every number in the PDF
from its JSON. Then commit and push.

---

## Appendix — numbers in this document and where they came from

| Claim | Source |
|---|---|
| 8-gram overlaps 0.1% / 1.4% / 48.7% | Computed in this session from the four `.tex` sources (method in §0) |
| Title-pair lexical overlap ≤ 4.8% | Computed in this session (Jaccard, content words) |
| MCP `notes.norm` leak | Reproduced in this session (§4.2) |
| `huggingface.co` refused (403); GitHub and PyPI reachable; `cargo` present | Checked in this session |
| 8.4–8.54 MiB; 41.1 MB/s; 17.9%; 237 leaked values | `paper/ijis/main.tex` abstract (J's results, quoted only to show the G2 overlap) |
| ai4privacy 3,973/3,973; CoNLL 173/173; TAB test 127 | `benchmarks/corpora/splits/*.json` |
