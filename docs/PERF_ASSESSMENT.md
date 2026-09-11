# Phase 1 — Technical Assessment: high-throughput streaming redaction

Scope: a read-only assessment of SafeStream-Redactor (as merged in `main`, ~4.8 K
LOC of `src/`, 30 test modules) against the goal of a production-grade,
high-throughput streaming redaction engine. **No implementation is proposed in
this document.** It ends with a direction (confirmed with the maintainer: a
native detection core) and an incremental plan whose first step is *not* a
rewrite.

The assessment is deliberately blunt about where the requested optimizations
(io_uring, mmap, zero-copy, SIMD-in-Python) would and would not move the number,
because several of them target a layer that is already ~1000× faster than the
actual bottleneck. Everything below is grounded in code that was re-read for this
pass and in measurements already in the repo (`docs/ZERO_COPY.md`,
`docs/PERFORMANCE_BACKENDS.md`, `docs/FORMAL_MODEL.md`).

---

## 0. The one fact that reframes the whole request

**This is a CPU-bound problem, and the CPU cost is CPython's regex engine — not
I/O, not copies, not syscalls.**

Measured (`benchmarks/zero_copy_read.py`, in-repo):

| Layer | Throughput | Relative |
| --- | --- | --- |
| input read + decode (`read_chunks`) | ~4.5 GB/s | ~2600× |
| mmap + `madvise(SEQUENTIAL)` decode | ~6.5 GB/s | ~3800× |
| **full redaction (detection dominated)** | **~1.7–3.1 MB/s/core** | **1×** |

Consequences that must anchor every later phase:

- **io_uring / mmap / preadv / sendfile / "zero-copy"** optimize input I/O, which
  is already ~2600–3800× faster than detection. Best case they change end-to-end
  throughput by <0.1%. `docs/ZERO_COPY.md` already measured and declined them.
- **SIMD in pure Python** is not a thing: the hot loop is `re.finditer` in C.
  The one place bytes are scanned in Python — the anchor prefilter — already
  dispatches to C-level `str.__contains__`/`memchr` (which is itself SIMD inside
  libc/CPython). There is no Python-level SIMD win available.
- The **only** levers that move a CPU-bound regex workload are: (a) a faster
  matching engine (compiled multi-pattern DFA / native code), and (b) more cores.
  (b) already exists (intra-file parallelism, ~3.7×/4 cores). (a) is the open
  frontier and requires leaving pure Python — hence the native-core decision
  (§11).

Applying the prompt's *own* engineering rules ("don't claim kernel-level/zero-copy
without benefit; benchmark before claiming; optimize the actual bottleneck")
forces this conclusion. It is not a reason to do less; it is the reason to spend
effort where it pays.

---

## 1. Current architecture

Cleanly layered, pure-Python, zero third-party runtime deps (only a `tomli`
backport on <3.11):

```
CLI (cli.py) ─┐        REST (api.py)      MCP (mcp_server.py)
              ├────────────► Redactor (redactor.py)  ◄── facade
              │                    │
   RedactionPolicy (policy.py)     │ orchestrates
                                   ▼
                  Streaming engine (engine.py)
                  stream_windows: rolling buffer + overlap window
                                   │  (pure; knows no detector internals)
                                   ▼
              Detection tiers (detectors/)  behind one Detector Protocol
              ├ deterministic.py  regex + validators (+ anchor prefilter)
              ├ entropy.py        Shannon-entropy secrets
              ├ contextual.py     trigger-word boost/suppress + bare-SSN
              ├ ner.py            optional spaCy (lazy)
              └ registry.py       entry-point plugins
                                   │
                  entities.resolve_overlaps (arbitration)
                                   ▼
                  RedactionPolicy.apply (replace/mask/pseudonymize)
                                   ▼
   Scaling:  scheduler.py (across files, RAM/CPU-aware ProcessPool)
             parallel.py  (one file split into ranges; seam cross-check)
   Cross-cutting: memory_budget.py (RLIMIT_AS), netguard*.py (egress),
                  report.py (stats), sarif.py, severity.py, calibration.py
```

The design's strongest idea — and the thing that makes it a *streaming* engine at
all — is `engine.stream_windows`: a rolling buffer of `chunk_size + overlap` that
emits only text ≥ `overlap` from the buffer end, retreating the emit boundary out
of any straddling detection. It is formally specified (`docs/FORMAL_MODEL.md`,
Thm 1) and property-tested.

## 2. Current data flow (file → file, the hot path)

`Redactor.redact_file` → `read_chunks` (64 KB text chunks, `errors="replace"`,
universal newlines) → `stream_windows(overlap=8 KB)` → per window
`Redactor.detect` (all tiers → contextual adjust → `min_confidence` filter →
`resolve_overlaps`) → `policy.apply` → write to a temp file → `os.replace`
(atomic). Memory is bounded by `chunk_size + overlap + L_max`, independent of file
size (`docs/FORMAL_MODEL.md`, Thm 3).

Parallel path (`workers>1`): split the file into ≥`4·overlap` byte ranges aligned
to char/`\r\n` boundaries; each worker streams its range with `overlap` scanned
pad + `overlap` context on each side; a **seam valve** cross-checks that adjacent
workers agree on every straddling detection and falls back to sequential on
disagreement; parts are concatenated in index order. Output is byte-identical to
the sequential pass (`docs/FORMAL_MODEL.md`, Thm 2; `tests/test_parallel.py`,
incl. a Hypothesis property).

## 3. Current bottlenecks (measured / located, not assumed)

1. **CPython regex detection — the dominant cost.** `DeterministicDetector.detect`
   runs up to ~23 compiled patterns per window; the anchor prefilter skips most on
   sparse text, but the *un-prefilterable* PII patterns (SSN, credit card, IPv4,
   IPv6, phone — all gated by digits, not distinctive literals) run on essentially
   every digit-bearing window. This is the ~3 MB/s ceiling.
2. **No single-pass multi-pattern matching.** Patterns run sequentially
   (`for pattern in self._patterns: finditer`). A `RegexSet`/DFA that matches all
   patterns in one pass is the classic fix — but blocked in-language by (3).
3. **Python-level per-detection object churn.** Each match allocates a `Detection`
   dataclass; `resolve_overlaps` sorts + bisects per window. Minor next to (1) but
   real at high PII density.
4. **`re2`/Vectorscan can't drop in.** Already evaluated
   (`docs/PERFORMANCE_BACKENDS.md`): 10/23 patterns use lookaround re2 can't
   compile, and re2's ASCII-only `\b`/`\w`/`\d` diverge from Python's Unicode
   semantics (it under-detects) — a correctness regression, and no end-to-end gain
   because the prefilter already covers its niche.
5. **Parallelism is per-file range-split, not a live pipeline.** Great for one big
   file at rest; it does *not* address a single unbounded live stream (stdin/
   socket), which stays single-core.

Not bottlenecks (measured): input I/O, decoding, buffer copies, syscalls, memory
bandwidth. Confirmed by §0.

## 4. Current memory behavior

- **Bounded and proven.** Working set ≤ `chunk_size + overlap + L_max` chars
  (`tests/test_memory.py` redacts 100 MB–1 GB under a flat <16 MB cap). Every span
  is length-bounded by construction (private-key body capped, entropy candidate
  capped) so `L_max = overlap = 8 KB`.
- **Admission + kernel enforcement.** `--memory-limit` sizes workers and, on
  Linux, sets a hard `RLIMIT_AS` cap (fail-closed exit 3). Conservative (bounds
  VSZ, not RSS).
- **Allocation profile is Python-object-heavy** (strings per chunk, `Detection`
  per match). No buffer pool — but in CPython a buffer pool buys little because
  the cost is object churn + regex, not `malloc`. A buffer pool matters *after* the
  hot loop moves to native code operating on `bytes`/`memoryview`.

## 5. Current I/O behavior

Plain buffered text-mode reads (`open(..., encoding=...).read(chunk_size)`) and
buffered writes to a temp file, `os.replace` for atomicity. No async, no mmap, no
vectored/direct I/O. **This is the correct choice today** (§0): I/O is 3+ orders
of magnitude off the critical path, and text-mode decoding + universal newlines is
exactly the semantics the detectors and the byte-identity guarantee depend on.

## 6. Current concurrency model

- **Across files:** `scheduler.redact_tree` — `ProcessPoolExecutor` sized by CPU
  and `/proc/meminfo` (`ram_aware_workers`), constant-memory workers.
- **Within a file:** `parallel.redact_file_parallel` — one `ProcessPoolExecutor`,
  N ranges, `pool.map`, ordered reassembly + seam valve.
- **No threads / no asyncio / no lock-free queues.** Processes (not threads)
  sidestep the GIL for the CPU-bound work — the right call in CPython. There is no
  inter-stage queue or backpressure loop because the model is "split up front, run
  N independent streams," not "reader → bounded queue → workers → ordered writer."

## 7. Current redaction / detection model

Detection and replacement are already cleanly separated (the prompt's Phase 12 is
largely satisfied): tiers emit `Detection(start,end,text,type,confidence)` spans;
`resolve_overlaps` arbitrates to a disjoint set; `policy.apply` performs one
left-to-right span rewrite. Offsets are span-based, not repeated string rebuilds,
though `apply` does build the output string per segment (unavoidable in Python;
cheap next to detection).

## 8. Major architectural weaknesses (vs the target)

1. **Language ceiling.** Pure CPython caps single-core throughput at ~3 MB/s for
   this regex workload. No in-language change breaks this materially.
2. **No live-stream pipeline.** A single unbounded stream is single-core; there is
   no reader→bounded-queue→worker-pool→ordered-writer topology with backpressure
   (the prompt's Phases 3, 9, 10, 11 as a *live* pipeline).
3. **No adaptive chunking.** `chunk_size`/`overlap` are static. (Phase 6.)
4. **Lookaround-bound patterns block any compiled engine.** SSN/card/IPv4/IPv6/
   phone use `(?<!…)`/`(?!…)`; no fast DFA engine (re2, Rust `regex`, Hyperscan)
   supports lookaround. Until these are rewritten as lookaround-free
   candidate+validator patterns *with Unicode-consistent boundaries*, no native
   engine can be byte-identical. **This is the critical-path correctness
   workstream, and it can be done entirely in pure Python first.**
5. **Observability is end-of-run only.** `RedactionStats` reports totals; there are
   no live gauges (throughput, queue depth, worker utilization). (Phase 16.)
6. **No resumability/checkpointing** for multi-hour files. (Phase 14.)

## 9. What must be preserved (non-negotiable)

- Public API: `Redactor`, `RedactionPolicy`, `EntityType`, `redact/detect/
  redact_file/redact_stream/detect_stream`, `netguard.enforced`,
  `scheduler.redact_tree`. Deprecate-first only.
- The three theorems: streaming equivalence, parallel byte-identity, constant
  memory — and their property tests. Any new engine is gated by
  `streaming_redact(x) == whole_redact(x)` across fuzzed chunkings **and**
  `new_backend(x) == python_backend(x)` including Unicode.
- Dependency-free default install + graceful fallbacks; offline guard; atomic
  writes; PII-never-in-logs; intellectual honesty in docs.

## 10. What should be redesigned / added

- **The detection core** → native (see §11), behind the existing `Detector` seam.
- **The pattern set** → lookaround-free candidate+validator form with explicit
  Unicode-consistent boundary classes (pure-Python, byte-identity-tested — the
  enabler for *any* compiled backend, and independently a small speedup).
- **A live streaming pipeline** (optional, for stream/stdin/socket inputs):
  reader → bounded chunk queue → worker pool → ordered writer, with backpressure.
- **Adaptive chunking**, **live metrics**, **checkpoint/resume** — in that
  priority order, each benchmark-gated.

## 11. Proposed target architecture (native-core direction — confirmed)

Keep the entire Python surface; replace only the hot loop.

```
             Python CLI / REST / MCP  (unchanged)
                        │
                 Redactor facade      (unchanged public API)
                        │
                 engine.stream_windows (unchanged; proven streaming/overlap)
                        │  hands each window (bytes/str) to:
                        ▼
        ┌─────────────────────────────────────────────┐
        │  Detector seam  (detectors/base.Detector)    │
        │                                              │
        │  backend="python"  → today's tiers (default, │
        │                       byte-identical oracle)  │
        │  backend="native"  → Rust core via PyO3       │
        │      • aho-corasick multi-literal prefilter   │
        │        (SIMD memchr) → candidate regions      │
        │      • regex crate RegexSet: all patterns in  │
        │        ONE pass, Unicode-aware \b/\d          │
        │      • candidate+validator for the (rewritten │
        │        lookaround-free) PII patterns          │
        │      • returns spans; Python does arbitration │
        │        + policy (or Rust does, later)         │
        └─────────────────────────────────────────────┘
```

Why this is the defensible path (and honest about cost):

- **It targets the measured bottleneck** (regex in C-Python → regex in Rust with a
  single-pass `RegexSet` + SIMD `aho-corasick` prefilter). Realistic target:
  10–100× single-core, then × cores.
- **Rust `regex` is Unicode-correct by default**, so it can match Python's `\b`/
  `\d` semantics — the exact thing that disqualified re2 — *provided* the patterns
  are lookaround-free (the `regex` crate, like all finite-automata engines, has no
  lookaround). Hence §10's pattern rewrite is the prerequisite, not optional.
- **Costs, stated plainly:** adds a Rust toolchain + `maturin`/PyO3 + a
  cross-platform wheel build matrix; and it **breaks "zero third-party deps" for
  users who opt in** to the native extra. Mitigation: pure-Python stays the
  default and the byte-identical fallback; `pip install safestream-redactor` stays
  dependency-free; `pip install 'safestream-redactor[native]'` (or a prebuilt
  wheel) opts in. Same pattern as the existing `[ner]` extra.
- **Correctness gate is absolute:** the native core ships only when a differential
  test proves `native.detect(x) == python.detect(x)` for the full corpus **and**
  Hypothesis-fuzzed Unicode inputs. If it diverges, it does not ship — the re2
  precedent stands.

Where the prompt's flashier items land, honestly:
- **SIMD:** yes — but *inside* the Rust core (`aho-corasick`/`memchr` are already
  SIMD; `regex` uses a lazy DFA). Not as hand-written Python.
- **io_uring / mmap / zero-copy:** still not worth it *until* the native core makes
  detection fast enough that I/O enters the top-3 costs. Re-benchmark then
  (`docs/ZERO_COPY.md` already says exactly this). Not in the initial native scope.
- **Live pipeline / adaptive chunking / backpressure:** orthogonal to the core;
  valuable for stream inputs; sequenced after the core proves out.

## 12. Prompt phase → current status (so we don't rebuild solved problems)

| Phase | Status |
| --- | --- |
| 1 Understand | **this document** |
| 2 Baseline | Partial — numbers exist (`ZERO_COPY`, README); needs a formal, repeatable multi-size/density harness (next step) |
| 3 Streaming data path | **Done** — constant-memory `stream_windows`; never loads whole file |
| 4 High-perf I/O | Evaluated & **declined with numbers** (`ZERO_COPY`); not the bottleneck |
| 5 Zero/min-copy | Partial/N-A in CPython; real once core is native (`bytes`/`memoryview` + buffer pool) |
| 6 Adaptive chunking | **Missing** — static sizes today |
| 7 Cross-chunk detection | **Done & proven** — overlap window + boundary retreat; Thm 1 + property tests (incl. split-at-every-position) |
| 8 Fast scanning (2-stage) | Partial — anchor prefilter is Stage-1; Stage-2 is the regex tier. SIMD only via native core |
| 9 Parallelism | **Done for files at rest**; live-stream pipeline missing |
| 10 Order preservation | **Done** — index-ordered part reassembly |
| 11 Backpressure | Partial — pull-based bounded by worker count; no inter-stage bounded queues (needed only for live pipeline) |
| 12 Redaction engine (span-based) | **Done** — detect→spans→arbitrate→apply |
| 13 Memory safety | **Done** — bounded spans, `RLIMIT_AS`, undecodable-byte accounting |
| 14 Fault tolerance | Partial — atomic writes + fallbacks; no checkpoint/resume |
| 15 Security | **Done** — content-free stats/reports, offline guard (+ hard modes), no PII in logs |
| 16 Observability | Partial — end-of-run stats; no live metrics |
| 17 Production API | **Done** — layered, core independent of UI |
| 18 Testing | **Strong** — 30 modules incl. property/differential/parallel/memory gates |
| 19 Benchmarking | Partial — several benches; needs the unified suite of Phase 2 |
| 20 Profiling | **Missing** — no committed perf/flamegraph workflow |
| 21 Documentation | **Strong** — README + FORMAL_MODEL + ZERO_COPY + PERFORMANCE_BACKENDS + this |

## 13. Recommended incremental plan (no big-bang rewrite)

Each step is independently shippable, benchmark-gated, and preserves byte-identity.

1. **Baseline harness (Phase 2).** One `benchmarks/baseline.py`: throughput, peak
   RSS, allocations, CPU%, core-scaling, across 10 MB/100 MB/1 GB × {none,low,med,
   high} PII density. Record results as the reference every later step is measured
   against. *(Pure Python, no risk.)*
2. **Lookaround-free candidate+validator pattern refactor (pure Python).** Rewrite
   SSN/card/IPv4/IPv6/phone to match a lookaround-free candidate then validate
   boundaries in code, with Unicode-consistent boundary handling. Gate on the
   existing differential + property tests (must stay byte-identical). This is the
   correctness foundation the native core needs — and a modest speedup on its own.
3. **Rust core scaffold behind `[native]` extra + `backend="native"`.** PyO3 +
   `maturin`; `aho-corasick` prefilter + `regex` `RegexSet`; returns spans to the
   existing Python arbitration/policy. Pure-Python remains default + fallback.
   Ship only when `native == python` byte-for-byte on corpus + fuzzed Unicode.
4. **Benchmark the core vs baseline; profile the new hot path** (perf/flamegraph);
   move arbitration/policy into Rust only if profiling says so.
5. **Then, if justified by re-measurement:** live streaming pipeline + adaptive
   chunking + live metrics + checkpoint/resume; and only *then* re-evaluate mmap/
   io_uring now that I/O may matter.

**Stopping here for your review of the assessment and the plan before any Phase-2
work.** The first implementation step (1: baseline harness) is low-risk and pure
Python; step 2 (pattern refactor) is the real correctness-sensitive foundation and
deserves its own review gate before the Rust toolchain lands.
