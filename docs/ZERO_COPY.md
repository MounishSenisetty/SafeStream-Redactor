# Zero-copy streaming: evaluation and decision

**Decision: not adopted (as of 0.4.x). Detection, not input I/O, is the
bottleneck, so zero-copy input cannot move end-to-end throughput — and adopting
it would add platform-specific code and risk the constant-memory invariant for
no measurable gain.** This document records the evaluation so the decision is
auditable and can be revisited if the detection tier ever gets much faster
(e.g. the Phase 3 Vectorscan/re2 backend).

Reproduce with `python benchmarks/zero_copy_read.py --size-mb 128`.

## What was evaluated

| Technique | Applicable to redaction? | Why |
| --- | --- | --- |
| `mmap` + `madvise(MADV_SEQUENTIAL)` | Input read only | Maps the file and hints sequential access; still pulls pages into userspace to scan. |
| `preadv` | Input read only | Vectored positional reads; avoids a seek + separate read, no serialization win here. |
| `splice` / `sendfile` | **No** | Kernel-to-kernel copy with *no userspace transformation*. Redaction rewrites the bytes, so output ≠ input; there is nothing to splice. Structurally inapplicable to a redactor. |

Only the input-read techniques are even candidates, because redaction must bring
every byte into userspace to scan and rewrite it.

## Measured (page cache hot, best of 3)

Generated log corpus (`benchmarks/zero_copy_read.py`), 64 KB chunks:

<!-- MEASURED:BEGIN -->
Measured on the dev container (shared/loaded, single-run, page cache hot) over a
16 MB synthetic log corpus — treat the absolute full-redaction figure as
environment-dependent (the README quotes ~3.1 MB/s on a quieter host); the
**ratio** between the layers is the point and is machine-independent:

| Variant | Throughput | vs `read_chunks` |
| --- | --- | --- |
| `read_chunks` (current, text mode + universal newlines) | ~4460 MB/s | 1.00× |
| `mmap` + `madvise(SEQUENTIAL)`, decode-only | ~6510 MB/s | 1.46× |
| `preadv`, decode-only | ~3790 MB/s | 0.85× |
| **full redaction** (I/O + decode + detection + policy) | ~1.7 MB/s | — |

Input I/O is **~2600–3800× faster** than full redaction.
<!-- MEASURED:END -->

## Reading the result

The three input-read variants all run **three to four orders of magnitude
faster** than full redaction: the decode/I/O layer is not on the critical path.
`mmap` + `madvise` is ~1.46× faster than `read_chunks` at the decode-only layer
(and `preadv` is actually slightly *slower* here), but since that layer is well
under 0.1% of end-to-end time, a 1.46× speedup on it is invisible in the total.
Full redaction throughput is set by the regex/validator detection tiers
(single-core; the known limitation the README states), so replacing
`read_chunks` with `mmap` or `preadv` changes end-to-end throughput by a rounding
error.

`mmap` also carries real costs against the project's guarantees:

- **Constant memory.** `read_chunks` holds exactly one `chunk_size` buffer.
  `mmap` maps the whole file into the process's *address space*; while resident
  memory stays bounded under `MADV_SEQUENTIAL` + `MADV_DONTNEED`, the virtual
  mapping is the file's full size, which interacts badly with the new
  `RLIMIT_AS` memory cap (a 100 GB `mmap` would need 100 GB of address-space
  headroom under the limit). `read_chunks` has no such interaction.
- **Byte-identity.** The sequential and parallel paths already share one
  decoder + universal-newline path (`engine.read_chunks` / `parallel._decode_bytes`).
  Swapping in `mmap` would fork that carefully-tested path for no gain.

## When to revisit

If Phase 3 lands a compiled-scanner backend (Vectorscan/re2) and single-core
detection jumps from ~3 MB/s to, say, ~300 MB/s, the I/O layer could become the
new bottleneck. At that point re-run `benchmarks/zero_copy_read.py`: if
`read_chunks` is then within ~2× of full redaction, an `mmap` + `madvise`
*input* reader (guarded to preserve constant address-space use under
`--memory-limit`, e.g. windowed mmap) becomes worth adopting behind a flag, with
the differential test proving byte-identical output. Until then, the simple
constant-memory reader is the right choice.
