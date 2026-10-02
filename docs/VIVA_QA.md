# Viva defence: likely questions and answers

Study material, three questions per domain (see [`CONTRIBUTIONS.md`](CONTRIBUTIONS.md)
for who owns which). The answers are written to be **derivable**: each cites the file
that makes it true, so you can reconstruct it rather than recite it. If you cannot
explain an answer without this page, you do not yet own that domain.

---

## D1 — Core engine and systems

**Q1. Theorem 1 needs `w ≥ max(L_max, C_left, C_right)`. What exactly breaks if `w < L_max`?**

An entity longer than the window can straddle a chunk boundary with neither window
ever holding it whole. The engine pulls the emit boundary back to a detection's start
(`engine._retreat_boundary`), but the carried tail is at most `w` characters, so a span
longer than `w` cannot be carried intact: sequential mode may cut it and leak part of it.
That is a redaction leak, not a crash, which is why it now **fails closed**:
`WindowConfigurationError` is raised if `overlap < min_safe_overlap` (static check at
construction, from each detector's declared `StreamingRequirements`) and if any detector
emits a span longer than `overlap` at run time (`engine._check_overlong`). Opt-out is
`--insecure-allow-leak-prone-overlap`. `tests/test_fail_closed_overlap.py` covers both.

**Q2. Why is memory constant, and why is output emitted exactly once?**

After each pass the engine keeps only `buffer[emit_upto:]`, at most `w` plus one
straddling span (`≤ L_max`); the next pass adds at most one chunk. So the buffer is
bounded by `chunk_size + w + L_max` independent of input (Theorem 3). Exactly-once: a
detection is yielded only in the pass where `d.end ≤ emit_upto`; the carried region is
disjoint from the emitted region, and detections that start in the read-only prefix are
dropped. If a plugin returned *overlapping* detections the retreat loop iterates to a
fixpoint, so a second straddler cannot be cut (`test_engine_kernel.py`).

**Q3. What does `RLIMIT_AS` actually guarantee, and what can `fanotify` not do?**

`--memory-limit` does two things: pre-flight admission control (refuses configs that
cannot fit, exit 3) and, on Linux, a kernel `RLIMIT_AS` cap at *current VSZ + budget*, so
an over-allocating run gets `MemoryError`/exit 3 instead of growing. The honest caveat
(`docs/MEMORY_ARCHITECTURE.md`): it bounds *virtual* address space, not RSS, and it only
ever tightens an existing limit. `fanotify` has no event exposing a `write()` payload
before it lands: `block` mode denies *reads* (`FAN_ACCESS_PERM` → `EPERM`), `redact`
rewrites after `FAN_CLOSE_WRITE`; `mmap` reads and 2-second directory rescans are
documented gaps. Rejecting a write in flight needs an LSM/eBPF hook or FUSE.

---

## D2 — Evaluation, benchmarking and security audit

**Q1. Your RedactionBench char-F1 is about 0.53 and 13.5 % of documents have no mandatory leak. Is the tool bad?**

On free-text prose without NER, mandatory recall is 0.71 and precision 0.75; names and
addresses are what a pattern engine does not see (`benchmarks/redactionbench/AUDIT.md`:
~45 % of mandatory misses are person names). The benchmark's `contextual` class is 57 %
of gold characters at ~47.7 % human agreement, so a near-1.0 score would not be
defensible. The claim is therefore *not* "high recall on prose"; it is "high precision
and exact, bounded-memory behaviour on structured PII and credentials", and the spaCy
tier trades precision (0.54) for recall (0.77 mandatory). We state this in the report.

**Q2. Why is "250–450× faster than Presidio" misleading, and what did you replace it with?**

The old row compared SafeStream's regex core against Presidio's *full* `AnalyzerEngine`,
which loads spaCy and runs NER on every document. That measures regex vs regex-plus-NLP.
`benchmarks/presidio_compare.py` now groups tools into like-for-like tiers: a pattern
tier (SafeStream deterministic tiers vs Presidio's own pattern recognizers run directly
with no NLP engine), and an NER tier (both on spaCy `en_core_web_sm`). Throughput,
memory and recall are reported per tier as a Pareto frontier. Hyperscan/re2 are not
measured here; `docs/PERFORMANCE_BACKENDS.md` documents why re2 was rejected (it
changes output on Unicode).

**Q3. A fuzzer is testing, not proof. What does `test_equivalence_fuzz.py` actually establish?**

It is evidence, not a proof, and says so. It compares `Redactor.redact` (whole) byte for
byte against streaming (random chunking, 1 char to multi-KB), the sequential file path,
and `redact_file_parallel` (random worker counts) on adversarial Unicode and undecodable
bytes, with entities written *across* chunk edges, the emit boundary
(`m·chunk − overlap`), the rescan prefix, and every seam chosen by `plan_ranges` itself.
Each example is guarded by `assume(max span ≤ overlap)`, i.e. Theorem 1's premise, so a
failure is a real violation, not an out-of-contract input. A planted bug (disabling
`_retreat_boundary`, or shrinking the overlap below the longest span) is detected, which
shows the harness can fail. It cannot cover unbounded detectors (A2 violated) and does
not replace the written proof.

---

## D3 — Platform, interfaces and integration

**Q1. What is the threat model of the MCP server and REST API? What never leaves the process?**

Both run offline: the network guard is on by default (best-effort `socket.connect`
patching; the docs say it is not a hard boundary, and the opt-in `--offline-hard` modes in `netguard_hard`
enforce it in the kernel, e.g. a fresh network namespace). The MCP tools return *metadata* (type, position, counts), never the matched
secret, and reports and SARIF carry `file:line:col` only. The residual risks are the
ones to state: an agent that can call `redact` on a path can read what that path's
redaction output contains, and plugin code runs with full process privileges, which is
why plugins load only with `--enable-plugins`.

**Q2. Why can the ONNX NER tier carry the equivalence guarantee when an LLM tier cannot?**

Theorem 1 assumes a bounded sliding-window function (A1: bounded span, A2: bounded
context). A token-classification model run per window over a fixed number of tokens
depends only on the window, so A2 holds with a measurable `C_left/C_right`; its declared
`StreamingRequirements` size the overlap. An LLM that conditions on the whole document
has unbounded context, violating A2, so neither theorem applies (`FORMAL_MODEL.md` §5).
Honest limit: a bring-your-own ONNX model must declare its context truthfully; an
under-declared tier is outside the contract.

**Q3. How do you know the native (Rust) backend and the Docker/wheel releases do not change behaviour?**

Byte-identity is a hard gate, not a benchmark: `tests/test_native_backend.py` compares
native and Python detections (including Unicode class tables generated to match Python),
and the equivalence fuzzer now also runs every property against `backend="native"`
whenever the extension is installed. Releases build manylinux/macOS/Windows wheels in
`native-wheels.yml` and multi-arch images with SBOM and provenance (`docker.yml`). The
rule is "do not merge a backend that changes output", which is exactly why the re2
prototype was rejected.
