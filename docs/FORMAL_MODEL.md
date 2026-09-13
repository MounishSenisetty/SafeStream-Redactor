# Formal Model — Provably-Equivalent Streaming Redaction

This document is the formal core of the research contribution described in
[`RESEARCH_PLAN.md`](RESEARCH_PLAN.md): a proof that SafeStream's streaming and
parallel execution produce the *same* output as a whole-document reference
execution, under stated assumptions whose constants are measured from the
implementation.

It fills work item **WI-2**. The correctness fix it depends on (**WI-1**) is
implemented: every detector now emits spans bounded by the default streaming
overlap, so the premise of Theorem 1 holds at the default configuration
(Section 3.3).

Every claim is mapped to the code that discharges it, by file and function, so
the document is checkable against the source rather than taken on faith.

---

## 1. Notation and objects

- `T` is the input text: a finite string over a Unicode character alphabet.
  `|T|` is its length in characters and `T[a:b]` is the half-open substring.
- A **detection** is a tuple `(i, j, type, conf)` with `0 <= i < j <= |T|`,
  a character span carrying an entity type and a confidence in `[0, 1]`
  (`entities.Detection`).
- A **detector** is a function `D : str -> list[Detection]` whose returned
  spans are offsets into the string it was given
  (`detectors/…`, each tier's `detect`).

### 1.1 The reference pipeline `Π`

`Π : str -> set[Detection]` is the whole-document reference. On input `T` it:

1. runs every configured detector tier on `T`
   (`Redactor.detect`, the `for detector in self._detectors` loop);
2. applies contextual scoring, which adjusts confidences using a bounded left
   window and contributes trigger-gated detections
   (`detectors/contextual.py`, `ContextualScorer.adjust` / `.detect`);
3. drops detections below `min_confidence`
   (`Redactor.detect`, `confident = [d for d in raw if …]`);
4. resolves overlaps into a sorted, pairwise-disjoint set
   (`entities.resolve_overlaps`).

`Π(T)` is the reference detection set. Redaction is a deterministic rewrite of
`T` given `Π(T)` (`policy.RedactionPolicy.apply`); because the rewrite is a pure
function of `(T, Π(T))`, equality of detection sets implies equality of redacted
output, so the theorems are stated over detection sets and the byte-identity of
output follows as a corollary.

### 1.2 The streaming engine `S_w`

`S_w` (`engine.stream_windows`, parameter `overlap = w`) consumes `T` as an
**arbitrary** sequence of chunks and yields `(segment, detections)` pairs. The
segments concatenate to exactly `T`; detection offsets are segment-relative.
Let `S_w(T)` be the union of yielded detections with offsets mapped back to
absolute positions in `T`. The chunking is not part of the result: the claim is
that `S_w(T)` is invariant across all chunkings and equal to `Π(T)`.

### 1.3 The parallel engine `P_{w,k}`

`P_{w,k}` (`parallel.redact_file_parallel`, `k = workers`) splits `T` into `k`
character-aligned byte ranges, redacts each range with `S_w` extended by scanned
pads and a context-only prefix, and reconciles range boundaries ("seams") with a
cross-check protocol (`parallel._redact_range`, the seam valve in
`redact_file_parallel`). `P_{w,k}(T)` is its emitted output.

---

## 2. Assumptions

The guarantees hold for any pipeline `Π` that is a **bounded sliding-window
function**. Two constants capture this.

- **A1 — bounded span length.** Every detection in `Π(T)` has length
  `j - i <= L_max`.
- **A2 — bounded context locality.** For every detection `s = (i, j, …)`,
  whether `s ∈ Π(T)` and its final confidence depend only on the substring
  `T[i - C_left : j + C_right]`. Equivalently, `Π` restricted to a window of
  radius `(C_left, C_right)` around any position returns the same verdict for a
  span in that window as the whole-document pass does.

A2 says the pipeline never needs more than `C_left` characters to the left or
`C_right` to the right of a span to decide it. A1 says no span is longer than
`L_max`. Together they make `Π` computable from bounded windows, which is what
makes streaming and parallel execution equivalent to the whole-document pass.

---

## 3. Audited constants

The constants are read from the implementation, not assumed. They are derived
**mechanically** from the `StreamingRequirements` each active detector declares
(`detectors/base.py`), taking the maximum over the *default* pipeline — the
detectors `Redactor()` actually installs. This is what the engine itself uses to
size its overlap (`engine.required_overlap`), so the audited constants and the
engine's behaviour cannot diverge. `tests/test_formal_constants.py` pins the
values below and fails if any future detector reads wider context, forcing this
document (and the paper) to be corrected in lockstep.

### 3.1 `C_left = 96`

The left-context reach of the default pipeline is set by the **label-anchored
identifier cascade** (`labeled_id.py`, `LabeledIdentifierDetector`), which is on
by default and reads a **96-character** cue→value window
(`_CUE_WINDOW = 96`, declared as `left_context=96`): a cue word such as
`Student ID` may sit up to 96 characters before the value it promotes. The base
tiers read less — the contextual scorer reads a 48-character left window
(`contextual.py`, `ContextualScorer.__init__(window=48)`), and the label-anchored
regex patterns (`AWS_SECRET`, `API_KEY`) fold their cue into the match itself — so
the cascade's 96 is the governing `C_left`. (Historically, before the cascade was
added, `C_left` was 48; the mechanical derivation above prevents that stale value
from persisting.) The opt-in semantic ensemble (`semantic_ensemble.py`) also
declares `left_context=96`, so enabling it does not raise `C_left`.

### 3.2 `C_right = 8`

The widest declared right-context in the default pipeline is the label-anchored
cascade's `right_context=8` (`labeled_id.py`), a conservative bound on the
trailing separators/suffix a cue→value match may consult; the underlying regex
reaches at most ~2 characters past the value. The base tiers reach less: the
widest right-context assertion elsewhere is the negative lookahead `(?!\.\d)` on
the phone and IPv4 patterns (`deterministic.py`), inspecting 2 characters, and
every validator (`luhn_ok`, `ssn_ok`, `ipv4_ok`, `ipv6_ok`, `phone_ok`) reads
only the matched text. The opt-in ensemble declares `right_context=32`, which
raises `C_right` to 32 when it is enabled — still far below the overlap.

### 3.3 `L_max = 8192` (after WI-1)

Historically two patterns had spans wider than the default overlap; **WI-1**
bounds both, so `L_max` now equals the default overlap `w = 8192` for every
tier:

| Pattern | Bound | Where |
| --- | --- | --- |
| `private_key` | key-type fields `{0,20}` + body `{1,8100}` + fixed markers ⇒ span `<= 8192` | `deterministic.py`, `EntityType.PRIVATE_KEY` |
| `secret` (entropy) | candidate `{20,8192}`; runs longer than 8192 emit as consecutive `<= 8192` spans | `entropy.py`, `_CANDIDATE`, `MAX_SPAN = 8192` |
| `secret` (compound) | candidate `{20,8192}` over an extended alphabet; same `MAX_SPAN` cap | `entropy.py`, `_COMPOUND_CANDIDATE`, `CompoundSecretDetector` |
| all other patterns | `< ~260` by construction | `deterministic.py` |

The private-key bound is exact: with the two `{0,20}` type fields, the two
16-character `PRIVATE KEY-----` markers, the `-----BEGIN ` / `-----END `
literals, and an `{1,8100}` body, the widest possible match is exactly 8192
characters (pinned by `test_max_private_key_span_fits_within_default_overlap`).

The entropy bound is by construction: the candidate regex can match at most 8192
characters, so no emitted span is wider (pinned by
`test_no_detector_emits_a_span_longer_than_default_overlap`). A high-entropy run
longer than 8192 characters is matched as *consecutive* capped spans covering the
whole run with no gap and no dropped tail — the regex carries neither a
lookbehind nor a lookahead, so `finditer` resumes inside the run
(`test_over_long_entropy_run_is_fully_covered_by_consecutive_spans`). This keeps
A1 true for every emitted span while still redacting the entire secret.

### 3.4 Consequence

```
max(C_left, C_right) = 96  <=  L_max = 8192  =  w = DEFAULT_OVERLAP
```

Both A1 and A2 hold at the default configuration, so
`w >= max(L_max, C_left, C_right)` — the premise of Theorem 1 — is satisfied
unconditionally at the default. `DEFAULT_OVERLAP`, the private-key bound, and
`MAX_SPAN` are kept in sync (see the cross-referencing comments in
`engine.py`, `deterministic.py`, and `entropy.py`).

---

## 4. Theorems

### Theorem 1 — Streaming equivalence

> Under A1 and A2, if `w >= max(L_max, C_left, C_right)`, then `S_w(T) = Π(T)`
> for every `T` and every chunking of `T`.

**Proof obligations, each mapped to code.**

**(a) Completeness — every reference span is seen whole in some window.**
The engine appends chunks to a rolling buffer and emits only the prefix of the
buffer that lies at least `w` characters from the buffer's end
(`emit_upto = len(buffer) - overlap`). Before emitting it retreats the boundary
to the start of any detection that straddles it
(`for det in detections: if det.start < emit_upto < det.end: emit_upto = det.start`).
The retreated tail — never more than one span, of length `<= L_max <= w` — is
carried into the next iteration (`buffer = buffer[emit_upto:]`). Hence any span
cut by a chunk boundary is reassembled and presented whole to `detect` in the
next window. ∎(a)

**(b) Soundness — no window produces a span absent from `Π(T)`.**
Each window is `detect(prefix + buffer)`, where `prefix` is the last `w`
characters already emitted (`engine.py`, `window_detect`). Because `w >= C_left`,
every span's full left context (`C_left` characters) is real text carried in
`prefix`, never an artificial chunk edge. Because a span is emitted only when it
ends at least `w >= C_right` characters before the buffer's live end
(`ready = [d for d in detections if d.end <= emit_upto]`), its right context is
likewise real text. By A2 the verdict and confidence computed in the window
equal the whole-document verdict, so no window can invent or mis-score a span.
Detections that fall inside `prefix` (already emitted) are dropped
(`if det.start >= 0`). ∎(b)

**(c) Exactly-once emission.**
A span is emitted in the unique segment whose `emit_upto` first exceeds its end
(`ready` filter), and the carried region `buffer[emit_upto:]` is disjoint from
the emitted region `buffer[:emit_upto]`. No span is emitted twice or skipped. ∎(c)

Together (a)–(c) give `S_w(T) = Π(T)`. Because the redaction rewrite is a pure
function of `(T, detection set)`, the streamed output is byte-identical to the
whole-document redaction. ∎

**Empirical corroboration.** `tests/test_streaming.py` and
`tests/test_properties.py` assert byte-identity for exhaustive small chunkings
and Hypothesis-generated inputs; `test_long_entropy_run_up_to_overlap_streams_identically`
covers a secret as long as the overlap.

### Theorem 2 — Parallel byte-identity, with safe fallback

> Under A1 with `w >= L_max`, `P_{w,k}(T) = S_w(T)` byte-for-byte. When A1 is
> violated at a seam, the seam valve detects the disagreement and `P_{w,k}`
> falls back to `S_w`; thus `P_{w,k}(T) = S_w(T)` **unconditionally**, and the
> parallel path never silently diverges from the sequential one.

**Proof obligations.**

1. **Aligned ranges reproduce the sequential substring.** Ranges split on
   character boundaries and `\r\n` pairs, and each range is decoded with the same
   incremental newline decoder the sequential reader uses
   (`parallel._align`, `_decode_bytes`), so a range's text is exactly the
   corresponding substring of the sequential pass.
2. **Each worker sees its seams in full context.** A worker prepends `w`
   characters of *scanned pad* and a further `w` of *context-only prefix* on each
   interior side (`_redact_range`, `_read_chars_before` / `_read_chars_after`,
   `initial_context=context`). With `w >= L_max` (A1) and `w >= C_left` (A2),
   every seam-crossing span is seen whole and with real left context — the
   Theorem 1 conditions, applied per range.
3. **Straddler ownership is unambiguous.** A span crossing a seam belongs to the
   **left** worker: the left worker renders and consumes it up to its end, and
   the right worker begins emitting at that end
   (`start_cut` / `end_cut` in `_redact_range`, `_find_straddler`). Both
   neighbours recompute the same seam independently from the same bytes.
4. **The valve enforces agreement.** The orchestrator compares each pair of
   neighbours' seam reports and, on any disagreement, discards the parts and
   redacts the whole file sequentially
   (`redact_file_parallel`, `if left.end_seam != right.start_seam: return sequential("seam")`).
   Disagreement is only possible when a span longer than `w` sits exactly on a
   seam — i.e. exactly when A1 is violated — so the valve converts every A1
   violation into a transparent fallback rather than a silent character loss or
   duplication.

Hence when A1 holds, parallel output equals sequential output byte-for-byte
(clauses 1–3); when it does not, the valve falls back (clause 4). Either way
`P_{w,k}(T) = S_w(T)`. ∎

The "unconditional equality via fallback" is the strongest single sentence of
the contribution: it is a guarantee competing tools do not state. After WI-1,
A1 holds at the default overlap, so the fallback is reserved for
out-of-guarantee inputs (e.g. a manually lowered overlap) rather than being
reachable by ordinary data.

**Empirical corroboration.** `tests/test_parallel.py` asserts parallel output is
byte-identical to sequential across worker counts, range sizes, encodings, and
seam-straddling entities, and exercises the fallback path directly.

### Theorem 3 — Constant-memory bound

> Peak working memory of `S_w` is `<= chunk_size + w + L_max`, independent of
> `|T|`. `P_{w,k}` uses at most `k` times that.

**Proof obligation.** After each emit the engine retains only `buffer[emit_upto:]`,
whose length is at most `w` plus one straddling span (`<= L_max`); the next
iteration adds at most one `chunk_size` chunk before emitting again
(`engine.stream_windows`). The buffer therefore never exceeds
`chunk_size + w + L_max` regardless of total input size. Each parallel worker
runs one `S_w` plus a `2w` holdback (`parallel._redact_range`), so total memory
scales with `k`, never with `|T|`. ∎

**Empirical corroboration.** `tests/test_memory.py` (the `memory` marker) tracks
peak allocations on large generated inputs and asserts a flat bound; the scale
curve substantiating the flat line to large sizes is
[`benchmarks/scale_memory.py`](../benchmarks/scale_memory.py) (WI-6).

---

## 5. Limitations — where the guarantee stops

Reviewers reward stating precisely where a guarantee ends. The assumptions fail
in exactly these cases, all of them detectable or documented:

- **A span longer than `w`.** After WI-1 no built-in detector produces one at the
  default overlap. It can still arise if a user lowers `overlap` below 8192, adds
  a custom detector with an unbounded span, or supplies a single high-entropy run
  longer than `w` that must be treated as one atom. In sequential mode such a span
  may be split at a chunk boundary; in parallel mode the seam valve catches it and
  falls back (Theorem 2). The over-long entropy run is redacted regardless — as
  consecutive `<= w` spans (Section 3.3).
- **A detector needing unbounded right context.** A2 fixes `C_right = 2`. Any
  future tier that must look arbitrarily far to the right — most notably an LLM
  tier that conditions on a whole document — breaks A2, and neither theorem
  applies to it. This is the principled reason the offline, bounded-window
  detectors are the ones that carry the equivalence guarantee.
- **Non-splittable encodings.** Only self-synchronising encodings (UTF-8,
  single-byte codecs) can be split for parallelism; others fall back to the
  sequential path by construction (`parallel.splittable_encoding`). Theorem 1
  still applies to the sequential path for any encoding.
- **Confidence constants.** The scoring constants (boost/suppress amounts,
  per-pattern base confidences) are inputs to `Π`, not part of the equivalence
  claim; the theorems hold for whatever `Π` is configured. Calibrating them
  (WI-9) changes `Π` but not the equivalence between `S_w`/`P_{w,k}` and `Π`.

---

## 6. Summary

| Guarantee | Statement | Discharged by |
| --- | --- | --- |
| **T1 Streaming equivalence** | `S_w(T) = Π(T)` for all chunkings when `w >= max(L_max, C_left, C_right)` | `engine.stream_windows`; `test_streaming.py`, `test_properties.py` |
| **T2 Parallel byte-identity** | `P_{w,k}(T) = S_w(T)` unconditionally (equal when A1 holds; safe fallback when it does not) | `parallel.py` seam valve; `test_parallel.py` |
| **T3 Constant memory** | peak `<= chunk_size + w + L_max`, independent of `|T|`; `k×` for parallel | `engine.stream_windows`; `test_memory.py`, `benchmarks/scale_memory.py` |

The novelty is not the engineering (overlap windows, prefiltering, seam
protocol) but the *guarantee* those mechanisms admit: that a bounded-memory,
parallel redactor produces the same output as an idealised whole-document pass,
with the one failure mode named and made safe.
