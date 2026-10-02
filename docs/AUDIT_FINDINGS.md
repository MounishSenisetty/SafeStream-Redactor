# Audit Findings — Production-Grade Hardening (Phase 0)

Read-only audit performed against branch `production-hardening`
(package version `0.4.0`, HEAD `4ae1137`). No source files were edited to produce
this report. It exists to be reviewed **before** any Phase 1 edits.

Scope of this pass:

1. Map every claim in `README.md` and `docs/AUDIT.md` to the code that implements
   it, with a real/partial/aspirational/missing status (§1).
2. Record the baseline verification suite — `pytest`, coverage, the memory proof,
   `ruff`, `mypy` — exactly as run, with results (§2).
3. Read the "kernel" (streaming buffer + overlap window, emit-boundary logic, tier
   arbitration / overlap resolution, parallel seam cross-check) line by line and
   list every correctness risk found (§3).

A short recommended Phase-1/2 ordering closes the document (§4). **Nothing here is
acted on yet.**

---

## 1. Claim → code → status

Status legend: **real** = implemented and tested; **partial** = implemented but with
a gap, weaker guarantee, or thin tests; **aspirational** = the wording over-states
what the code enforces; **missing** = no implementation found.

### 1.1 README — headline guarantees

| # | Claim (README) | Implemented by | Status | Note |
|---|---|---|---|---|
| C1 | Constant **O(1) memory**; "redact a 100 GB file with the same footprint as a 1 KB one" | `engine.stream_windows`; `redactor.redact_file` → `read_chunks`/`stream_transform` | **real** | Proven by `tests/test_memory.py` (memory marker). Peak bounded by `chunk_size + overlap + L_max` (FORMAL_MODEL Thm 3). |
| C2 | Overlap window catches entities that straddle chunk boundaries; "any entity up to `overlap` (default 4 KB at audit time; 8 KB since R-DOC-1) is always seen whole at least once" | `engine.stream_windows` (emit-boundary retreat), `required_overlap`, per-detector `StreamingRequirements` | **real, wording drift** | Code default overlap is **8 KB** (`DEFAULT_OVERLAP = 8*1024`), README §Architecture says "default 4 KB". FORMAL_MODEL uses 8192. Doc inconsistency (R-DOC-1). |
| C3 | Emit boundary that would split a detection "retreats to the detection's start" | `engine.stream_windows`, lines 108-112 | **real** | Correct **iff** detections are non-overlapping (see R-ENG-1). |
| C4 | Already-emitted text kept as read-only left context so contextual tier scores identically to whole-text mode | `engine.stream_windows` `window_detect` + `prefix` carry | **real** | Matches FORMAL_MODEL Thm 1(b). |
| C5 | Parallel single-file split is **byte-identical** to single-core, seam cross-check falls back on disagreement | `parallel.redact_file_parallel` (seam valve), `_redact_range` | **real, example-tested** | Correct by construction + `test_parallel.py`; but coverage is example-based, not exhaustive/property-based (R-PAR-3). |
| C6 | Anchor prefilter skips regexes that cannot match; "provably identical output (a differential test compares prefiltered and unfiltered detection)" | `detectors/deterministic.py` (`anchors`, `needs_digit`, `_prefilter`); `tests/test_prefilter.py` | **real, not a hard gate** | The differential test exists but is an ordinary test, not a required/parametrised gate over the whole pattern set + fuzzed inputs (R-DET-1). |
| C7 | Offline network guard blocks non-loopback egress by default; "best-effort … not a hard boundary" | `netguard.install` (monkeypatches `socket.connect`/`connect_ex`); CLI installs by default | **real & honestly scoped** | Only TCP `connect`; UDP `sendto`, native syscalls, subprocesses bypass. Honesty is good; Phase 2 adds hard mode. |
| C8 | `--memory-limit` "runs within a stated budget and *fails closed* (exit 3) rather than over-allocating" | `memory_budget.MemoryBudget.plan`; `cli._plan_budget`; exit-code 3 path | **partial / aspirational** | It is **pre-flight admission control only**: it refuses to *start* when the *estimate* exceeds budget. It does **not** cap runtime allocation — a runaway pass over-allocates freely. README wording implies enforcement stronger than exists (R-MEM-1). This is precisely Phase 2's target. |
| C9 | MCP server exposes offline scan/redact, "metadata only, never the secret" | `mcp_server.py`; `tests/test_mcp.py` | **real** | Not re-audited line-by-line here (outside the kernel); tests present. |
| C10 | CI/CD gate: `--fail-on-detect`, SARIF, pre-commit hook, GitHub Action | `cli.py`, `sarif.py`, `.pre-commit-hooks.yaml`, `action.yml` | **real** | Covered by `test_cli.py`, `test_sarif.py`, `test_ci_integrations.py`. |
| C11 | Extensible plugin tiers via entry points, each declaring streaming boundary requirements | `detectors/registry.py`, `detectors/base.StreamingRequirements`, `engine.required_overlap` | **real** | Plugin `detect` output is trusted to be non-overlapping and span-bounded; not enforced (R-ENG-1, R-ENG-4). |
| C12 | Atomic file writes ("never a partial output") | `redactor.redact_file` (mkstemp + `os.replace`), `parallel` merge via tmp + replace; `tests/test_atomic_writes.py` | **real** | Same-file overwrite rejected; temp cleaned on error. |
| C13 | Constant-memory **parallel** (memory scales with worker count, never file size) | `parallel._redact_range` holdback bounded by `2*overlap` | **real** | FORMAL_MODEL Thm 3; not independently memory-proofed under the `memory` marker for the parallel path (R-PAR-4, minor). |
| C14 | Deterministic pseudonyms (same input → same token) via HMAC | `policy.py` pseudonymize mode | **real** | `test_redaction.py`; not kernel. |
| C15 | Non-UTF-8 handling: undecodable bytes "reported and warned about" | `read_chunks(errors="replace")`, `RedactionStats.decode_replacements`, CLI warning | **real, coverage caveat** | Undecodable bytes become U+FFFD and are **not scanned** — a genuine coverage hole, surfaced honestly via the stat/warning rather than fixed. Acceptable but worth a Phase-1 regression test pinning the count across sequential vs parallel (R-ENC-1). |

### 1.2 README — evaluation / benchmark claims

| # | Claim | Backed by | Status |
|---|---|---|---|
| C16 | "Synthetic and self-generated" corpora; recall figures are format coverage, not real-world recall | `benchmarks/`, README caveat box | **real (honest labelling)** — matches the "intellectual honesty" constraint. |
| C17 | ~3.1 MB/s throughput, "a known limitation, not a strength" | `benchmarks/run_benchmark.py` | **real, unverified here** — number not re-measured in this pass; Phase 3 will benchmark and may replace with an re2/Vectorscan backend behind a flag. |
| C18 | ~3.7× on 4 cores for single-file parallel | `benchmarks/parallel_speedup.py` | **real, unverified here** — not re-measured. |
| C19 | Vectorscan/re2 backend "stays on the roadmap" | `docs/ROADMAP.md` | **missing (by design)** — this is Phase 3 work. |

### 1.3 Public API surface (the non-negotiable contract)

All present and importable — verified by import and by `__init__.py`/module inspection:

| Symbol | Location | Status |
|---|---|---|
| `Redactor`, `RedactionPolicy`, `EntityType`, `RedactionMode` | `redactor.py`, `policy.py`, `entities.py` | **real** |
| `Redactor.redact / detect / redact_file / redact_stream / detect_stream` | `redactor.py` | **real** |
| `netguard.enforced` (+ `install`/`uninstall`/`is_installed`) | `netguard.py` | **real** |
| `scheduler.redact_tree` | `scheduler.py` | **real** |
| `RedactionStats` returned by `redact_file` | `report.py` | **real** (AUDIT.md's old "redact_file returns nothing" finding is already fixed). |

These must not break; any change requires deprecate-first. No changes proposed in Phase 0.

### 1.4 docs/AUDIT.md scorecard — reconciliation

`docs/AUDIT.md` is the **older** v0.1.0 audit. Several gaps it lists are already
closed on this branch; noting them so we don't "fix" solved problems:

| AUDIT.md gap | Current state |
|---|---|
| "No property-based tests or coverage gate" | **Closed** — `tests/test_properties.py` exists; coverage gate at 95% enforced in `pyproject.toml`. Phase 1 will *extend* property coverage (overlap fuzzing, cross-boundary injection), not create it. |
| "No anchored-prefix prefilter" | **Closed** — implemented in `deterministic.py`. |
| "Single large file is single-core" | **Closed** — `parallel.py` splits one file across cores. |
| "Non-atomic output writes" | **Closed** — atomic mkstemp+replace. |
| "Silent plugin failures" | **Partial** — `registry.load_plugins` still needs review for diagnostics (not in this kernel pass). |
| "redact_file returns nothing actionable" | **Closed** — returns `RedactionStats`. |
| "No SECURITY.md / threat model" | **Closed** — `SECURITY.md` present. |

**Recommendation:** `docs/AUDIT.md` should be marked as the historical v0.1.0 audit
and cross-linked to this document, so the two aren't read as contradictory.

---

## 2. Baseline verification suite

Environment: Python 3.11.15, Linux. The `pytest`/`mypy`/`ruff` console shims are
isolated `uv` tools **without** the package on their path, so the suite is invoked
as `python -m pytest` / `python -m mypy` (an environment quirk worth documenting for
web sessions; the packaged tools work once `pip install -e '.[dev]'` targets the
same interpreter).

| Command | Result |
|---|---|
| `python -m pytest -q` | **330 passed, 1 skipped, 1 deselected** in ~7.7 s |
| `python -m pytest --cov=safestream_redactor -q` | **96.19%** total coverage — **above the 95% gate**. Lowest modules: `cli.py` 91%, `memstream/events.py` 93%, `netguard.py` 94%, `scheduler.py` 94%. |
| `SAFESTREAM_MEMTEST_MB=100 python -m pytest -m memory -o addopts=''` | **1 passed** (347 s). Constant-memory proof holds: peak < 16 MB redacting a 100 MB file. (A 30 MB local repeat also passed.) |
| `ruff check .` | **All checks passed** |
| `ruff format --check .` | **63 files already formatted** |
| `python -m mypy` | **Success: no issues found in 29 source files** (strict) |

Skipped/deselected detail:

- **1 skipped**: `tests/test_memstream_wal.py` — `safestream_redactor.memstream.wal`
  does not exist yet (a WAL spec landed ahead of the module; the test skips until it
  lands). Not a regression; unrelated to the redaction kernel.
- **1 deselected**: the `memory`-marked proof, excluded from the default run by
  `addopts` (by design).

**Baseline verdict:** green across the board. Every Phase-1/2 change must keep it
green (coverage ≥ 95%, ruff clean, mypy strict clean, memory proof passing) at each
step, per the constraints.

---

## 3. Kernel correctness risks

The "kernel" = `engine.py` (streaming buffer + overlap window + emit boundary),
`entities.py` (`resolve_overlaps` arbitration), and `parallel.py` (seam cross-check).
Read line by line. Each risk below is tagged with a severity and whether it is a
**latent bug**, a **robustness/fail-open gap**, a **doc drift**, or an
**under-tested invariant**.

### Engine (`engine.py`, `stream_windows`)

- **R-ENG-1 — boundary retreat assumes non-overlapping input (robustness, medium).**
  The retreat loop (`if det.start < emit_upto < det.end: emit_upto = det.start`) and
  the `ready = [d for d in detections if d.end <= emit_upto]` filter are correct
  **only** because the pipeline's `Redactor.detect` runs `resolve_overlaps` before
  handing detections to the engine. `stream_windows` itself takes an arbitrary
  `detect` callable and only *documents* the "must return non-overlapping" contract.
  If a custom/plugin detector (or a future caller of `stream_windows`/`detect_stream`)
  returns overlapping spans, two spans can straddle the same boundary and one can be
  silently split at emit time — a **fail-open** (text emitted un-redacted). Worked
  example: dets `B=[80,95]`, `A=[90,105]`, `emit_upto=100` → A retreats it to 90,
  leaving B straddling 90 and dropped from `ready`; B's `[80,90]` is emitted
  un-redacted. Fix direction: have `stream_windows` defensively `resolve_overlaps`
  (or assert disjointness) rather than trust the caller; add a regression test with
  deliberately overlapping detections.

- **R-ENG-2 — `overlap < required` is a warning, not a guardrail (fail-open, medium).**
  `Redactor.__init__` logs a warning when `overlap < min_safe_overlap` but proceeds.
  With `overlap` below `C_left` (48) or below a detector's `max_span`, streaming
  equivalence silently breaks (entities straddling a boundary can be missed or
  mis-scored). A logged warning is easy to miss in a pipeline. Fix direction: keep
  the escape hatch but make it explicit (e.g. require an opt-in flag to run below
  `min_safe_overlap`, or raise by default), and add property tests that assert the
  *documented* failure mode rather than silent divergence.

- **R-ENG-3 — buffer growth under a position-0 straddler (bounded, low; needs a
  pinning test).** When the retreat drives `emit_upto <= 0` the engine `continue`s and
  keeps appending chunks. Analysis shows the buffer stays bounded
  (`< 2*overlap + chunk_size`, consistent with Thm 3) because a span is `<= L_max =
  overlap`, but there is no explicit regression test that a detection anchored at
  offset 0 with length ≈ overlap keeps memory flat. Add one.

- **R-ENG-4 — unbounded custom span defeats the overlap sizing (fail-open, medium).**
  `required_overlap` derives the window from each detector's declared
  `StreamingRequirements`, but a plugin that under-declares `max_span` (or omits it,
  taking the 8 KB default) while actually emitting longer spans will have those spans
  cut at boundaries. The engine trusts the declaration. Fix direction: at minimum
  detect at runtime when an emitted span exceeds the configured overlap and
  warn/annotate (parallel mode already catches this at seams via the valve; sequential
  mode does not).

- **R-ENG-5 — final-window right context at true EOF (verified correct, no action).**
  The trailing `if buffer: yield buffer, window_detect(prefix, buffer)` scores the
  last bytes with no right context; correct because the reference pass also has no
  text past EOF. Noted so it isn't re-flagged.

### Arbitration (`entities.py`, `resolve_overlaps`)

- **R-ARB-1 — sweep is correct; documented for the record (no action).** The
  bisect-based greedy sweep keeps highest-confidence, tie-break longer-span-then-start.
  Verified: kept intervals stay sorted and disjoint, and a candidate can only collide
  with `kept[i-1]` (proof: earlier kept intervals end no later than `kept[i-1].start`).
  Ties are deterministic. This matches the reference `Π`, so streaming/parallel
  equivalence is preserved. No bug.

- **R-ARB-2 — greedy ≠ maximum-weight (by design, doc only).** The resolver is
  greedy-by-confidence, not a maximum-weight independent set, so in principle a single
  high-confidence span can suppress two lower ones whose combined "value" is higher.
  This is intentional (keep the most-confident label) and is part of `Π`; not a
  correctness risk against the reference. Worth one sentence in FORMAL_MODEL to
  pre-empt reviewer questions.

- **R-ARB-3 — confidence equality after calibration (low).** With a `Calibrator`,
  `predict_one` can produce equal floats across tiers; the sort is stable and the
  tie-break deterministic, so output is stable. Add a targeted test so a future sort
  key change can't silently reorder arbitration.

### Parallel seam cross-check (`parallel.py`)

- **R-PAR-1 — seam agreement relies on A1/A2 holding within the pads (correct;
  under-tested, medium).** Each worker carries `overlap` scanned pad + `overlap`
  context on each interior side, so both neighbours of a seam compute the same
  straddler verdict *when* `max(C_left,C_right) <= overlap` and `L_max <= overlap`.
  The valve then compares `SeamReport`s and falls back on any disagreement. The logic
  is sound, but the guarantee is only exercised by hand-picked examples. Phase 1
  should make this **exhaustive**: a Hypothesis property fuzzing content, worker count,
  and range boundaries, asserting `parallel == sequential` byte-for-byte and that any
  forced disagreement falls back (the existing `test_seam_disagreement_falls_back`
  monkeypatches one case only).

- **R-PAR-2 — `entity_type` included in seam equality (correct; note).** `SeamReport`
  compares `rel_start/rel_end/entity_type`. Because both workers see the straddler with
  full in-pad context, A2 guarantees identical type; the equality is therefore a real
  cross-check, not an over-tight one. Fuzzing (R-PAR-1) should confirm no false
  fallbacks on in-guarantee inputs.

- **R-PAR-3 — universal-newline seam handling (correct; pin it).** `_align` nudges
  past `\r\n` pairs and `_decode_bytes` uses `IncrementalNewlineDecoder(translate=True)`
  to match the sequential reader. A lone `\r` at a seam flushes to `\n` via the
  decoder's final flush, and a boundary is never placed between `\r` and `\n`.
  `test_crlf_and_lone_cr_across_seams` covers this; fold it into the property sweep so
  CRLF/loose-CR positions are fuzzed, not just sampled.

- **R-PAR-4 — parallel constant-memory not under the `memory` marker (low).** Thm 3
  claims `k×` memory for parallel, but the `memory` proof only covers the sequential
  path. A parallel memory proof (small `SAFESTREAM_MEMTEST_MB`, `workers>1`) would make
  the claim testable, not just argued.

### Memory budget & netguard (guarantee-strength gaps → Phase 2)

- **R-MEM-1 — `--memory-limit` is admission control, not enforcement (aspirational
  vs README, high for Phase 2).** `MemoryBudget.plan` refuses to start when the
  *estimated* per-worker working set exceeds the budget and derives a worker cap; it
  never bounds actual heap growth. README C8 ("runs within a stated budget and fails
  closed rather than over-allocating") reads stronger than the code enforces. Phase 2
  target: back it with a hard `RLIMIT_AS` (`resource.setrlimit`) and/or cgroup v2
  `memory.max` on Linux so the kernel fails the process closed (exit 3), keeping the
  current estimate as the pre-flight check and as the fallback on unsupported
  platforms. Until then, the README sentence should be softened to "pre-flight
  admission control" to match the code (honesty constraint).

- **R-NET-1 — guard covers TCP `connect` only (documented; Phase 2 hard mode).**
  `netguard` patches `socket.connect`/`connect_ex`. UDP `sendto` to a non-loopback
  address, `ctypes`/native syscalls, and subprocesses all bypass it. This is stated
  honestly in `netguard.py` and `SECURITY.md`. Phase 2 target: opt-in hard mode via
  `unshare(CLONE_NEWNET)` and/or a seccomp-bpf filter blocking `connect`/`sendto` to
  non-loopback, with a graceful, clearly-labelled fallback and no overclaiming.

- **R-NET-2 — `0.0.0.0`/`::` treated as loopback (low).** `_LOOPBACK_HOSTS` includes
  the "any" addresses `0.0.0.0`/`::`, which are not loopback. Edge case; worth a note
  and possibly tightening when Phase 2 revisits the guard.

### Encoding

- **R-ENC-1 — undecodable bytes are unscanned (coverage hole, surfaced not fixed;
  low).** `errors="replace"` turns undecodable bytes into U+FFFD before any detector
  sees them, so a secret hiding in mis-encoded bytes can pass through. This is honestly
  surfaced via `RedactionStats.decode_replacements` and the CLI warning. Phase 1 should
  add a regression test asserting the replacement **count matches** between the
  sequential and parallel paths (they use different decoder setups), so the two can't
  silently diverge on malformed input.

### Documentation drift found while auditing

- **R-DOC-1 — overlap default stated as 4 KB in README, 8 KB in code/FORMAL_MODEL.**
  README §Architecture says "default 4 KB"; `DEFAULT_OVERLAP = 8*1024` and
  FORMAL_MODEL use 8192. Align the README to the code (never the reverse).
- **R-DOC-2 — `docs/AUDIT.md` describes v0.1.0** and lists gaps already closed (see
  §1.4). Mark it historical and link to this file.

---

## 4. Suggested ordering for Phase 1 / Phase 2 (for your review — not yet started)

Phase 1 (correctness first, small commits, each with regression tests):

1. **R-ENG-1**: make `stream_windows` robust to overlapping detections
   (defensive `resolve_overlaps` / assert) + regression test. *(highest-value: turns
   a documented contract into an enforced one; closes a fail-open path.)*
2. **R-ENG-2 / R-ENG-4**: turn the silent under-overlap / under-declared-span
   warnings into explicit, tested behaviour (opt-in to run degraded; runtime
   over-long-span detection in sequential mode).
3. **Property tests**: extend `test_properties.py` to fuzz `chunk_size` **and**
   `overlap` **and** boundary position, injecting entities across boundaries, asserting
   byte-identical vs whole-file (R-ENG-3 pinning included).
4. **R-DET-1**: promote the prefilter differential check to a required, parametrised
   gate over the full pattern set on fuzzed inputs.
5. **R-PAR-1/2/3**: a Hypothesis property proving `parallel == sequential`
   byte-for-byte across worker/range/boundary fuzzing, plus forced-disagreement
   fallback; fold CRLF/lone-CR into it.
6. **R-ENC-1, R-ARB-3, R-PAR-4**: targeted regression tests.

Phase 2 (make the guarantees real at the kernel level):

7. **R-MEM-1**: `RLIMIT_AS` / cgroup v2 `memory.max` enforcement behind
   `--memory-limit`, fail-closed exit 3, pure-Python admission control as fallback;
   soften README wording immediately to match today's behaviour.
8. **R-NET-1/2**: opt-in `unshare(CLONE_NEWNET)` / seccomp-bpf hard mode with precise
   docs on coverage.
9. Zero-copy streaming evaluation (mmap/madvise/preadv/splice) — adopt only where it
   measurably helps *and* preserves constant memory and byte-identical output.

Phase 3 (performance): prototype re2/Vectorscan backend behind a flag, gated by the
differential test; report real numbers.

---

## 5. Phase 1 status (correctness first) — complete, pending review

Implemented on this branch in small, verified commits. Baseline stayed green at every
step (343 fast tests + memory proof passing, coverage 96.24%, ruff + mypy strict clean).

| Finding | Action taken | Where |
|---|---|---|
| **R-ENG-1** | Emit-boundary retreat now iterates to a fixpoint, so a span is never cut even when a caller passes overlapping detections (previously a fail-open). Non-overlapping path unchanged. | `engine._retreat_boundary` + `tests/test_engine_kernel.py` |
| **R-ENG-4** | Runtime guard warns once per stream when a detection exceeds the overlap, instead of silently risking a boundary miss. | `engine._warn_if_overlong` + `tests/test_engine_kernel.py` |
| **R-ENG-3** | Zero-anchored / straddling-at-0 retreat pinned by unit tests. | `tests/test_engine_kernel.py` |
| **Streaming invariant** | Property tests now fuzz `overlap` **and** `chunk_size` together, plus drive one entity across a boundary at every position, asserting byte-identical vs whole-file. | `tests/test_properties.py` |
| **R-DET-1** | Prefilter differential check promoted to a generative Hypothesis gate over fuzzed input. | `tests/test_prefilter.py` |
| **R-PAR-1** | Parallel==sequential byte-identity proven by a Hypothesis property fuzzing content, worker count, and range boundaries (existing test covers forced-disagreement fallback). | `tests/test_parallel.py` |
| **R-ARB-3** | Deterministic tie-break in `resolve_overlaps` pinned. | `tests/test_properties.py` |
| **R-ENC-1** | Already covered — `test_invalid_utf8_bytes_mid_range` asserts decode-replacement parity between sequential and parallel; no new test needed. | `tests/test_parallel.py` (existing) |
| **R-DOC-1 / R-DOC-2** | README overlap default corrected to 8 KB; `docs/AUDIT.md` marked historical and cross-linked. | `README.md`, `docs/AUDIT.md` |
| **R-MEM-1 (partial)** | README `--memory-limit` wording softened to "pre-flight admission control" to match today's code; the real `RLIMIT_AS`/cgroup enforcement is Phase 2. | `README.md` |

**Deliberately left for Phase 2** (privileged / kernel-level, worth a review
checkpoint before touching): **R-MEM-1** hard enforcement (`setrlimit`/cgroup v2),
**R-NET-1/2** `unshare`/seccomp hard mode, and the zero-copy streaming evaluation.
**R-ENG-2** (under-overlap warning → hard failure) was intentionally **not** changed to
raise-by-default *at the end of Phase 1* (superseded: construction now raises by default, and
§9 closes the runtime half): `min_safe_overlap` is the *worst-case* declared span (8192), and small
entities legitimately run with a small overlap (the property/streaming tests themselves
use overlap 64-256); raising would break that valid, memory-constrained use. The honest
mitigations are the existing `__init__` warning plus the new runtime over-long-span
warning (R-ENG-4). Flagging for your call if you'd prefer an explicit opt-in flag instead.

**Phase 1 stopped here for review before Phase 2 (kernel-level guarantees).**

---

## 6. Phase 2 status (real kernel-level guarantees) — complete, pending review

Implemented in small, verified commits. Baseline green at every step
(376 fast tests + 100 MB memory proof passing, coverage ≥ 96%, ruff + mypy strict
clean). Systems code (ctypes syscalls) is proven by real forked-child tests and
covered in-process with fakes so no irreversible syscall touches the test runner.

| Finding | Action taken | Where |
|---|---|---|
| **R-MEM-1** | `--memory-limit` now backed by a hard **`RLIMIT_AS`** kernel cap (current VSZ + budget) on Linux/POSIX: over-allocation raises `MemoryError` → CLI **exit 3**, failing closed at the kernel instead of Python-side accounting. Main process + each parallel worker capped; only ever tightens a pre-existing lower cap; graceful admission-only fallback where unsupported. cgroup v2 `memory.max` documented as the complementary container-runtime mechanism (an unprivileged process can't self-apply it). | `memory_budget.enforce_address_space_limit`, `cli._plan_budget`, `parallel._init_worker`; `tests/test_memory_enforcement.py` |
| **R-NET-1/2** | Opt-in **`--offline-hard`** kernel modes: `seccomp` (seccomp-bpf filter blocking `AF_INET`/`AF_INET6` socket creation process-wide, native code included) and `netns` (`unshare(CLONE_NEWNET)` into an empty namespace), plus `auto`. Applied before workers fork; fail closed to a warning where unsupported; docs state exactly what each does and does not cover. | `netguard_hard.py`, `cli._apply_offline_hard`; `tests/test_netguard_hard.py` |
| **Zero-copy** | Evaluated `mmap`+`madvise`, `preadv`, `splice`/`sendfile` with a benchmark. Input I/O is ~2600–3800× faster than detection, so it is not on the critical path; **not adopted** (would also fight the `RLIMIT_AS` cap and fork the shared decoder). splice/sendfile structurally inapplicable (redaction rewrites bytes). Decision + numbers documented. | `benchmarks/zero_copy_read.py`, `docs/ZERO_COPY.md`, ROADMAP |

**Honesty note.** Everything above is best-effort where the platform is: hard
modes and `RLIMIT_AS` are Linux/POSIX and degrade to clearly-labelled fallbacks
elsewhere; the `RLIMIT_AS` cap is deliberately conservative (bounds VSZ, may
refuse slightly before RSS reaches the budget); seccomp blocks IP-socket
*creation* (loopback included) because classic BPF cannot filter `connect()` by
address. README, SECURITY.md, and MEMORY_ARCHITECTURE.md were updated to match.

**Remaining for Phase 3 (performance):** the Vectorscan/re2 backend behind a
feature flag, gated by the differential test, reporting real numbers — the one
headline limitation still standing.

## 7. Phase 3 status (performance backend) — complete, pending review

Prototyped and benchmarked a compiled-regex (google-re2) backend for the
deterministic tier, ran the differential comparison, and — as the guardrail
"don't merge a backend that changes output" requires — **did not adopt it**. The
differential check did its job: it caught that the backend changes output.

| Finding | Evidence |
| --- | --- |
| re2 can't compile the throughput-dominating patterns | 10/23 patterns fail (`ssn`, `credit_card`, `ipv4`, `ipv6`, `phone`, `aws_secret`, `anthropic_key`, `openai_key`, `private_key`) — lookaround / large repetition |
| re2 **changes output** on Unicode (safety regression) | its `\b`/`\w`/`\d` are ASCII-only vs Python's Unicode-aware; 5/5 Unicode probes diverge with re2 **under-detecting** (e.g. matching an email Python correctly rejects) |
| re2 gives **no end-to-end speedup** | 1.00× on a realistic PII log, 0.89× on credential-dense text — the prefilter already captures re2's fast-no-match win, and the costly PII patterns stay in Python |
| Hyperscan/Vectorscan hits the same wall | same lookaround + ASCII-boundary limits, heavier native dep — documented, not pursued |

Deliverables: `benchmarks/re2_backend.py` (reproducible prototype + correctness +
throughput), `docs/PERFORMANCE_BACKENDS.md` (findings + decision + the real
prerequisite: a semantics-preserving lookaround-free / Unicode-consistent pattern
rewrite), README + ROADMAP updated. `google-re2` is a benchmark-only extra; the
shipped `pip install` stays dependency-free and the backend is **not** shippable
as-is (it would under-redact Unicode text).

## 8. Overall — all four phases complete

Every finding from §1–§3 is addressed or explicitly, honestly deferred with
reasons. The public API is unchanged, the constant-memory invariant holds (the
100 MB memory proof passes after every phase), and coverage stays ≥ 95% with
ruff + mypy strict clean throughout. Two guarantees the README described as
best-effort are now real at the kernel (`RLIMIT_AS` memory enforcement; opt-in
seccomp/netns offline containment); two tempting optimisations (zero-copy I/O, a
compiled regex backend) were evaluated with real numbers and honestly declined,
with the docs updated to match the code rather than the reverse.

---

## 9. Phase 5 — fail-closed windows, mechanical equivalence check, benchmark framing

**R-ENG-2 / R-ENG-4 (closed).** Before this phase only the *construction-time* check was
fail-closed (`Redactor` raised if `overlap < min_safe_overlap`); the *runtime* check for a
detector emitting a span longer than the overlap — the case a plugin or custom regex that
under-declares `StreamingRequirements` actually produces — still only logged a warning.
Now both raise `engine.WindowConfigurationError` (a `ValueError`, so existing handlers
keep working): `stream_windows(strict_spans=True)` is the default, `Redactor` and the
parallel workers forward `allow_unsafe_overlap`, and the CLI accepts
`--insecure-allow-leak-prone-overlap` (alias of `--allow-unsafe-overlap`). A custom
regex's span cannot be bounded statically, so the guarantee for it is the runtime check;
the run halts and, through `atomic_output`, leaves no partial output file.
Tests: `tests/test_fail_closed_overlap.py`.

**Claim C5 / Theorems 1–2 (evidence strengthened, still evidence not proof).**
`tests/test_equivalence_fuzz.py` compares whole vs streaming vs sequential-file vs
parallel byte-for-byte over adversarial Unicode and undecodable bytes, with entities
written across chunk edges, the emit boundary, the rescan prefix and every parallel seam
(seams are read from `plan_ranges`). A `deep`-profile run (3000 examples for each streaming
property, 1000 for the parallel one) found no counterexample. Two planted mutants (`_retreat_boundary` disabled; overlap
shrunk below the longest span) are both detected. During construction the harness hit a
Hypothesis 6.168 shrinker crash with differently-alphabeted `st.text` nodes; generators
use `sampled_from` lists to avoid it.

**R-DOC-1 (re-opened and closed).** `SYSTEM_DESIGN.md` still stated a 4 KiB default in six
places (one contradicted itself by also citing an 8 KiB PEM bound), and
`examples/policy.toml` shipped `overlap = 4096`, which the fail-closed guard rejects, so
the documented example config could not start. All corrected to 8192;
`tests/test_docs_consistency.py` now fails on a stale default and builds the example policy.

**Claims C17/C18 and the Presidio comparison (re-measured).** The "250–450× faster than
Presidio" figure compared the native core with Presidio's full spaCy engine. The harness now
reports like-for-like tiers (see `benchmarks/PRESIDIO_COMPARISON.md`): **15–147×** pattern
tier, **~2×** NER tier (with SafeStream using ~2.5× more memory there). One run, shared
4-vCPU container, no repeats. Hyperscan/re2, gitleaks and the ONNX tier remain unmeasured.

---

## 10. Phase 6: architecture audit of the operators and regional tier (findings A-H)

An SOLID/clean-architecture audit of `operators.py`, `detectors/regional.py`, `policy.py`,
`engine.py` and `redactor.py`. Every finding below was **reproduced with a script before it
was fixed**, and each fix has a regression test. Fixes landed in `ac09625` (A, B, E, 7) and
`16f360e` (H, F, D).

### Closed

| ID | Finding | Resolution | Regression test(s) |
|---|---|---|---|
| **A** | `hmac_key`, `hash_salt` and `encrypt_key` appeared in `repr()` of a `RedactionPolicy`, so a traceback or log line could leak them (`hmac_key` was pre-existing; the pattern was copied). | `field(repr=False)` on all three. | `test_policy_repr_never_shows_key_material` |
| **B** | A missing `cryptography` was reported as a wrong key: `Deanonymizer._decrypt` had `except Exception`, which swallowed the `ImportError`. An `encrypt` policy was also accepted without the library and failed only on the first match, mid-stream. | `require_crypto()` runs when an encrypt policy or a `Deanonymizer` is built (`MissingExtraError`); decryption catches only `InvalidTag` and malformed-payload errors; the CLI prints a clean message. | `test_encrypt_policy_fails_fast_without_the_extra`, `test_a_missing_extra_is_never_reported_as_a_wrong_key`, `test_cli_reports_a_missing_extra_as_a_clean_error` |
| **E** | Silent non-restoration: a 40,000-character span (reachable with `overlap=60000`) encrypted to a 53,386-character token, larger than the restorer's fixed 48,000-character buffer. It was split across chunks, never decrypted, **never counted**, and `deanonymize` exited 0. | `MAX_PLAINTEXT_BYTES = 32_768`; `encrypt_token` raises `OperatorError` past it; `_MAX_TOKEN` is derived from that bound. | `test_encrypt_refuses_a_span_it_could_not_restore` (the largest permitted value round-trips through 997-character chunks) |
| **7** | No common error root. The existing domain exceptions derive from three unrelated builtins (`ValueError`, `RuntimeError`, `Exception`); the new code raised bare `ValueError`/`ImportError`. | `errors.SafeStreamError`; `WindowConfigurationError`, `MissingExtraError` (also `ImportError`) and `OperatorError` (also `ValueError`) derive from it, so existing `except` clauses keep working. | `test_error_hierarchy_has_one_root_and_stays_backward_compatible` |
| **H** | `StreamingRequirements.streaming_safe` was documented as disabling streaming but nothing read it, so a detector declaring it could not run on windows was silently streamed (fail-open). | `Redactor` raises `WindowConfigurationError` at construction. `stateful` stays **advisory** (documented as such) so third-party plugins that pass it keep working. | `test_redactor_refuses_a_detector_that_declares_streaming_safe_false`, `test_stateful_is_advisory_and_does_not_block_construction` |
| **F** | IBAN matching accepted free-form spacing (`GB82 W E S T 1 2 3 ...`); the worst-case span stayed under the declared `max_span` only by accident. | Only the electronic form and the print form (groups of four, last group 1-4) are accepted. | `test_iban_accepts_the_canonical_forms`, `test_iban_rejects_non_canonical_spacing`, `test_longest_iban_span_fits_the_declared_requirement` |
| **D** | Encrypted output was not scan-clean: the base64 payload tripped the entropy tier (three `secret` findings at 0.6 on a rescan), so `detect --fail-on-detect` over `--mode encrypt` output would fail. | Token format change: the payload is written in **groups of 16 joined by `.`**. The entropy candidates need a 20+ character run from fixed alphabets that exclude `.`, so no run in a token can reach the minimum. | `test_encrypted_output_raises_no_findings_on_rescan`, `test_no_ciphertext_run_is_long_enough_for_the_entropy_candidates`, `test_grouped_tokens_still_round_trip` |

### Decisions and trade-offs

* **D was reshaped, not exempted.** An exemption (skip entropy findings inside a
  `<TYPE:E:...>` envelope) would have to recognise a token mid-window, but a token can be
  up to ~44K characters and the window's left context is only `overlap` (8 KiB by
  default). The decision would then depend on unbounded left context, violating assumption
  **A2** of `docs/FORMAL_MODEL.md` and breaking the streaming == whole-document guarantee.
  Reshaping the token is window-local, identical for the Python and native backends (the
  native parity gate is untouched), and holds by construction rather than by a heuristic.
  The format changed because `encrypt` had not been released.
* **H halts construction, deliberately.** Every entry point except `Redactor.redact` feeds
  detectors bounded windows, so a detector that needs the whole input would miss entities
  that straddle a boundary. Raising in the constructor protects the streaming invariant at
  the price that such a detector cannot be used with `Redactor` at all, not even through
  `redact()`. That is the intended fail-closed behaviour; a plugin author who needs
  whole-document analysis must run it outside the streaming pipeline.
* **`stateful` is advisory.** Removing the field would break any plugin that constructs
  `StreamingRequirements(stateful=True)`; the proof assumes window-pure detectors and a
  stateful one documents its own guarantees.

### Open: known and tracked for a dedicated patch

| ID | Finding | Evidence |
|---|---|---|
| **C** | `fictionalize` is not a fixed point: its output is re-detected (`example.com` emails, TEST-NET addresses), so redacting the output again changes it. | `usercd7610b9@example.com` -> `user727f0a35@example.com` and `192.0.2.50` -> `203.0.113.51` on a second pass. A document should be redacted once, or the reserved ranges exempted from detection. |
| **G** | Deterministic-tier card recall (existing code, not introduced here): a Luhn-valid card followed by a space and digits is mishandled. | `card 4111 1111 1111 1111 10.1.2.3` -> `card [REDACTED].1.2.3` (the card swallows the IP's first octet and the rest leaks); in a variant where the card follows `...example` and the address is detected first, the card itself stayed unredacted. Reproduced twice; the root cause is **not yet isolated** (suspected: the card candidate greedily absorbs the next digit group, then loses overlap resolution). Needs a regression test in `tests/test_detectors.py` before any change. |

### Open design items from the same audit (no behavioural defect)

* **OCP:** adding an operator touches six places (enum, `__post_init__`, `render`, CLI
  choices, config schema, MCP strategy enum). Recommended: an `Operator` protocol and a
  registry, keeping the `mode="hash"` strings.
* **OCP/DIP:** `RegionalDetector.detect` hard-codes eight rule blocks and `redactor.py`
  carries `REGIONAL_TYPES`. Recommended: a rule table and a `produces` declaration on the
  detector.
* **Exceptions:** `NetworkAccessError`, `ResourceExhaustionError`, `WatchUnavailable`,
  `MCPError`, `SettingsError` and `InputError` are not yet under `SafeStreamError`.
* **ISP:** `RedactionPolicy` carries key material for every operator; `Redactor.__init__`
  has 24 parameters.

