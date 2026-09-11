# Memory Architecture

This document explains **exactly** how SafeStream-Redactor stays within a memory
budget, and — just as importantly — what the budget does and does not cover. It
deliberately avoids the vague "constant memory" claim; the precise statement is
below.

## 1. The streaming invariant (what was always true)

The engine processes text in a sliding window (`src/safestream_redactor/engine.py`).
It holds one chunk plus a bounded `overlap` tail carried between iterations, and
never accumulates the whole input. The formal statement (`docs/FORMAL_MODEL.md`,
Theorem 3) is:

> Peak **application working set** ≈ `chunk_size + overlap + L_max` characters,
> independent of total input size,

where `L_max` is the longest span any active detector can emit. There is no code
path in the core that reads an entire file into memory — `redact_file` streams
input chunks and streams redacted output to a temp file, then atomically renames.

`benchmarks/scale_memory.py` measures this empirically: redact files across a
16 MB → 1 GB range and the peak Python-heap allocation (via `tracemalloc`) is a
flat line, not a growing one.

## 2. The budget (what is new in 0.4.0)

The invariant says memory is *bounded*; it did not let an operator *choose* the
bound and refuse to run above it. `safestream_redactor.memory_budget` adds that.

```
safestream redact big.log -o clean.log --memory-limit 64MB --workers 8
```

`MemoryBudget.plan(chunk_size, overlap, requested_workers, max_workers)`:

1. Estimates one worker's peak working set:
   `STREAM_CHAR_FACTOR * (chunk_size + overlap) * bytes_per_char + per_worker_fixed`.
   `STREAM_CHAR_FACTOR = 4` is a conservative upper bound on the characters live
   at the busiest instant (buffer + prefix + the transient `prefix+buffer`
   detection string + emitted segment + redacted segment ≈ `3·chunk + 4·overlap`).
2. Sets aside a `model_budget` (for an NER/ONNX model loaded once) and a reserve
   fraction (default 15%).
3. Admits the largest worker count whose aggregate estimate fits, capped by both
   the requested workers and the CPU count.
4. **Fails closed** — raises `ResourceExhaustionError` — if even one worker does
   not fit. The CLI turns this into exit code **3** and a message naming the
   limit and the largest chunk size that would fit. It never silently shrinks
   buffers or falls back to whole-file loading.

This admission step runs *before* any work starts: *if the estimate does not fit,
we refuse*, and the estimate is deliberately larger than reality so the true peak
stays under the number you asked for.

### 2.1 Kernel enforcement — `RLIMIT_AS` (new)

Admission control alone cannot *stop* an allocation the estimate did not
foresee (a pathological input, a mis-declared plugin). On Linux/POSIX the budget
is therefore also backed by a **hard kernel cap**: after admission,
`enforce_address_space_limit(growth_bytes)` reads the process's current virtual
size (VSZ, from `/proc/self/statm`) and sets `RLIMIT_AS` to *current VSZ +
budget*. From that point the kernel refuses any `mmap`/`brk` that would grow the
process past the cap — the offending allocation raises `MemoryError`, which the
CLI catches and turns into the same **exit 3**. Over-allocation now *fails
closed at the kernel*, not just in Python-side accounting.

- **Main process**: capped at *current VSZ + `--memory-limit`* (it streams in the
  sequential path and lightly orchestrates in the parallel path).
- **Each parallel worker**: `parallel._init_worker` lowers `RLIMIT_AS` to its own
  *current VSZ + per-worker budget*, so a single runaway worker fails closed on
  its own share rather than the whole budget.
- **Only ever tightens**: a pre-existing lower hard limit (e.g. a container
  `--memory`/cgroup cap) is preserved, never raised.

**Honest caveat.** `RLIMIT_AS` bounds *virtual* address space, which can exceed
resident memory (glibc arenas, thread stacks, `mmap` reservations). The cap is
therefore **conservative**: it may refuse slightly *before* RSS reaches the
budget, never after — the same "err toward earlier refusal" direction as the
admission estimate. That is the safe direction for a fail-closed guarantee.

**Fallback.** On platforms without `resource`/`RLIMIT_AS` (e.g. Windows), or when
`/proc/self/statm` can't be read, enforcement is skipped and the CLI prints a
warning; the run continues under admission control only. `setrlimit` is never
allowed to crash the run — a rejected call degrades to the same fallback.

**Complementary container limits.** A cgroup v2 `memory.max` (via
`docker run --memory=…` or systemd) is a stronger, whole-container bound but must
be set by whoever owns the cgroup — an unprivileged process cannot move itself
into a delegated cgroup and write `memory.max`. SafeStream therefore enforces the
in-process `RLIMIT_AS` cap it *can* set unprivileged, and defers container-level
enforcement to the runtime. Both compose: the tighter of the two wins.

## 3. Working set vs. RSS vs. page cache (the honest part)

The budget bounds the **application-managed working set** — the live Python
strings the pipeline holds. It does **not** bound process RSS, which additionally
includes:

| Consumer | Scales with input? | Covered by `--memory-limit`? |
| --- | --- | --- |
| Streaming buffers (chunk + overlap + spans) | No (bounded) | **Yes** |
| Interpreter baseline (~15–40 MB) | No | No — reported separately |
| Imported modules + compiled regexes | No | Partly (per-worker fixed term) |
| OS page cache for the file | No (reclaimable) | No — it is the kernel's, not ours |
| Optional NER/ONNX model | No | Carved out as `model_budget` |

If you set `--memory-limit` below the interpreter baseline, the CLI **warns**
that the budget bounds the working set, not total RSS. Conflating the two would
be exactly the false "constant memory" claim this project refuses to make.

The formal memory equation the budget enforces:

```
M_estimate = workers · (STREAM_CHAR_FACTOR·(chunk+overlap)·bytes_per_char + per_worker_fixed)
           + model_budget
           + reserve
           ≤ total_limit
```

## 4. Adaptive concurrency and backpressure

- **Across files** (`scheduler.py`): the process pool is sized by
  `ram_aware_workers`, clamped by CPU and `/proc/meminfo` availability, so a
  large corpus never fans out past what RAM allows. `--memory-limit` tightens
  this cap further via the budget plan.
- **Within a file** (`parallel.py`): a large file is split into
  character-aligned byte ranges, one per worker, with output byte-identical to
  the sequential pass. The number of ranges is bounded by the worker count, so
  there is no unbounded queue of in-flight chunks.
- **Backpressure**: because processing is pull-based (each worker streams its own
  range and writes directly), there is no producer that can outrun consumers into
  an unbounded queue. Concurrency is the only knob, and the budget bounds it.

## 5. Why this is safer than "just use chunks"

A naive chunker still lets worker count, a pathological long line, or a model
load blow past available RAM with no warning. Here, the worker count is a
*function of the budget*, the per-span length is *bounded by construction* (every
pattern caps its span; see `deterministic.py` and `entropy.MAX_SPAN`), and an
over-budget configuration is *refused* rather than attempted. The failure mode is
a clean, structured error — not an OOM kill halfway through a 1 TB file.

## 6. Reproducing the numbers

```bash
python benchmarks/scale_memory.py --sizes 16 64 256 1024
python benchmarks/scale_memory.py --sizes 16 64 256 --workers 4
```

The flat peak-memory column against a growing input size is the empirical proof
of the invariant; the budget is what turns that property into an enforceable
operational contract.
