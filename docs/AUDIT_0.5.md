# Score audit: throughput, DLP enforcement, precision (0.5 native work)

A score for three dimensions after the 0.5 native-core and DLP work, against
measurements in this repository, not estimates. Scores are 1–10. The starting point
was an overall 4/10, with the native backend at 5.3–13.6 MB/s end to end (10 MB,
one worker) and no file-system enforcement. Every number cites the file it comes from.

## Summary

| Dimension | Score | What sets it |
| --- | --- | --- |
| Throughput | **7** | 10–35 MB/s per core end to end, 36–121 MB/s on four workers, flat memory; still Python-orchestrated per detection |
| DLP enforcement | **6** | real kernel enforcement of reads, in-place redaction, honest fallback; no write interception |
| Precision / recall | **6** | excellent on structured PII, weak on names and free text; one real false positive removed |

The target was 8+ on all three. None reaches it, for the reasons below. The work that
would close each gap is listed at the end.

## Throughput — 7

Evidence (`docs/NATIVE_CORE.md`, `benchmarks/baseline.py`):

- 200 MB `redact_file`, native: **34.5 MB/s** (1 % PII) and **10.4 MB/s** (50 %) on one
  worker; **120.7** and **36.5 MB/s** on four. Pure Python: 1.3 / 1.1 and 5.2 / 2.1.
  At the start of this work the native backend ran 5.3–13.6 MB/s end to end
  (10 MB, one worker); before the previous round, 1.4–1.9 MB/s.
- Every default tier runs natively: deterministic (~140 MiB/s), labeled identifiers
  (~130 MiB/s), entropy (~530 MiB/s), compound secrets (~960 MiB/s).
- Memory is flat: ~43 MB RSS for the parent, ~37 MB per worker, at 200 MB.
- Output is byte-identical to the Python tier on every run (identical detection
  counts; differential and Hypothesis gates on every tier, mutation-checked).

Why not 8: per-detection work is still Python — `Detection` objects, overlap
resolution and replacement — so throughput falls 3x from sparse to dense input,
and a single core does 10–35 MB/s where compiled scanners do hundreds of MB/s.

## DLP enforcement — 6

Evidence (`docs/FANOTIFY.md`, `tests/test_watch.py`):

- `safestream fanotify --mode block` denies `read()` of any watched file that holds a
  detection, through `FAN_ACCESS_PERM`, verified against the real kernel (`cat` and
  `cp` get `EPERM`; a cleaned file reads again). Verdicts are cached per file version;
  unscannable files are denied (fail closed).
- `--mode redact` rewrites files atomically after the writer closes them; `--mode
  audit` logs content-free findings.
- Without `CAP_SYS_ADMIN`, audit and redact fall back to inotify; block refuses to
  start rather than run unenforced. CI runs the kernel tests as root.

Why not 8: `fanotify` cannot see a write's data, so nothing stops a secret from being
*written*; `mmap` reads are not covered; new directories are marked by a 2-second
rescan; `redact` leaves a short window between close and rewrite; Linux only; no
packaging (service unit, hardening, tamper resistance).

## Precision / recall — 6

Evidence (`benchmarks/PRESIDIO_COMPARISON.md`, `benchmarks/run_benchmark.py`):

- Structured PII in noisy logs: entity recall 1.000, character precision 0.999
  (Presidio: 0.856 / 0.737). Caveat: a self-generated corpus.
- RedactionBench (real documents, all labels): character precision **0.75**,
  character recall **0.41**, entity recall **0.44**; with spaCy NER 0.55 / 0.54 /
  0.52. Presidio: 0.40 / 0.37 / 0.64.
- E.164 country codes: removes the one `+` false positive on RedactionBench (a
  `+0000` timezone offset) and loses no gold phone. Real, but small.
- The Rust and Python tiers agree exactly, including on Unicode class edges.

Why it stays at 6: on real text more than half of the sensitive characters are
missed without NER, and the NER that raises recall costs a quarter of the precision.
"Zero false negatives" and "zero false positives" are not properties any tool here
has.

## What would reach 8

- **Throughput:** fuse the pipeline in Rust for the built-in tiers — arbitration,
  thresholding and replacement for the replace/mask modes — so Python only sees the
  final spans; anchored scanners for SSN and the labeled rules (the two remaining
  full-text DFA passes).
- **DLP:** an eBPF LSM (`file_permission`) or FUSE layer to inspect writes before they
  land; `FAN_PRE_ACCESS` on file systems that support it for `mmap`; mount marks for
  complete coverage; a systemd unit with capability bounding.
- **Precision/recall:** a stronger on-device NER (a transformer or GLiNER-class model
  through the existing ONNX tier), with thresholds calibrated on RedactionBench, to
  lift recall on names and addresses without the spaCy tier's precision loss.
