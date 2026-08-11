# ADR 0001 — Intra-file parallel redaction

- Status: accepted
- Date: 2026-08-11

## Problem

Single-file redaction was single-core. The engine streams a file through one
process at a measured ~3 MB/s, so a 100 GB log takes hours while the other
cores sit idle. The multi-file scheduler (`scheduler.py`) already uses every
core *across* files, but a single large file — the exact shape of a big log or
database dump — got no parallelism at all. This was the last headline
limitation called out in the roadmap.

The hard constraint is that redaction is security-sensitive: a faster path that
changes the output is not acceptable. Whatever we build must produce the same
bytes the trusted sequential path produces, or it is not usable.

## Alternatives considered

1. **Compiled regex backend (Vectorscan/RE2) behind the `Detector` seam.**
   Attacks throughput from the constant-factor side and would help every mode.
   Rejected *as the first step* because it is a large dependency and porting
   surface, it does not use idle cores, and it does nothing for the
   Python-level tiers (contextual, entropy, NER). Still worthwhile later; it is
   orthogonal to this change.

2. **Split the file at chunk boundaries and let each worker stream a slice,
   concatenating outputs.** This is the naive version of what we chose and it is
   wrong as stated: a detection straddling a slice boundary is seen by neither
   worker in full, and left-context-dependent scoring (the contextual tier)
   differs from whole-text mode near the cut. Draft 3 of the roadmap rejected
   exactly this for those reasons.

3. **Range split with overlap pads and a seam-ownership protocol** (chosen).
   Keeps the existing streaming engine untouched as the per-range worker, adds a
   thin coordination layer that makes seams invisible, and *verifies* the seams
   agree rather than trusting the math.

## Decision

Split the input into character-aligned byte ranges. Each worker redacts its
range with the ordinary streaming engine, extended on both sides:

- an `overlap`-sized **scanned pad** on each side, so a worker sees every
  detection crossing its seams in full;
- a further `overlap` of **context-only prefix** (via the engine's new
  `initial_context` parameter), so the first scanned character has the same left
  context the sequential pass gives it.

**Seam ownership.** A detection crossing a seam (a *straddler*) belongs to the
**left** worker: the left worker renders it and consumes the straddled
characters; the right worker starts emitting at the straddler's end. Both
neighbours compute the straddler independently from the same bytes.

**Seam valve.** The orchestrator checks that both sides of every seam reported
the identical straddler (offsets and type). If any seam disagrees — only
possible for inputs outside the engine's documented guarantee, e.g. an entity
longer than `overlap` sitting on a seam — the whole file is redacted
sequentially instead. This makes character loss or duplication at a seam
*structurally* impossible: parallel mode either matches the sequential pass or
becomes the sequential pass.

Character-boundary alignment covers UTF-8 (skip continuation bytes) and
single-byte codecs (any offset is safe); other encodings fall back. A `\r\n`
pair is never split, because the reader collapses it to `\n` under
universal-newline translation and cutting between the bytes would desynchronise
the parallel text from the sequential text.

## Contract

For entities no longer than `overlap` — the engine's existing cross-boundary
guarantee — parallel output is **byte-identical** to `Redactor.redact_file`,
for any worker count and any seam placement. Entities longer than `overlap` are
best-effort in *both* modes (this predates parallelism); parallel mode never
loses or duplicates a character in that regime, but which over-long spans get
redacted may differ from the sequential pass. Tests assert byte-identity in the
guaranteed regime and a no-corruption property (re-redacting either output
whole-text yields the same canonical text) in the over-long regime.

## Consequences

- **Positive.** Near-linear speedup up to core count (measured ~3.7× on 4
  cores, byte-identical output). The streaming engine is reused unchanged, so
  the constant-memory property holds per worker; total memory scales with worker
  count, never with file size. The valve means a correctness bug in the seam
  math degrades to "slower", never to "wrong output".
- **Negative / costs.** More moving parts than a single stream: temp part-files
  in the destination directory (cleaned up on all paths), process-pool startup
  cost (hence the `MIN_RANGE_BYTES` floor below which we don't bother), and a
  small amount of re-scanned text at each seam (`~2*overlap` per seam). The
  over-long-entity divergence from sequential is a real sharp edge, documented
  and tested rather than hidden.
- **Follow-ups.** A compiled-regex backend (alternative 1) stacks on top of
  this for a further constant-factor win. Raising the guaranteed entity length
  would shrink the over-long divergence window but costs memory; left as a
  tuning knob (`overlap`).
