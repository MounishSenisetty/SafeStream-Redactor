# Native detection core — plan and DFA-readiness of the pattern set

This is the working doc for the native (Rust/PyO3) detection core decided in
`docs/PERF_ASSESSMENT.md`. It records the outcome of Phase-2 **step 2**: making the
tier-1 patterns expressible without lookaround (the prerequisite for any
finite-automaton engine — Rust `regex`, RE2, Hyperscan — since none support
lookaround), proven byte-identical to the Python tier.

## Pattern DFA-readiness (measured)

Every tier-1 pattern now falls into one of three buckets:

| Bucket | Patterns | Native handling |
| --- | --- | --- |
| **Already lookaround-free** (13) | email, jwt, aws_key, github_token, slack_token, slack_webhook, stripe_key, google_api_key, sendgrid_key, twilio_key, npm_token, url_credentials, api_key, private_key | Drop straight into a Rust `regex` `RegexSet` (single-pass, Unicode-correct `\b`/`\d`). |
| **Rewritten lookaround-free** (6) | ssn, ipv4, ipv6, aws_secret, anthropic_key, openai_key | `detectors/_lookaround_free.py` — DFA-compatible candidate + code boundary check, **byte-identical** to the originals (`tests/test_lookaround_free.py`, corpus + 800 fuzz examples in CI, 20 000 ad-hoc). Port candidate → `RegexSet`, boundary check → Rust. |
| **Need a dedicated scanner** (2) | credit_card, phone | Greedy variable-length core over a separator-containing alphabet + negative lookahead ⇒ regex backtracking a candidate+filter cannot reproduce (measured: 104 / 175 / 1644 divergences). Handle verbatim in the native core (see below). |

So **19 of 21** patterns become a single-pass `RegexSet`; **2** get a targeted
path. This is the concrete artifact the Rust core ports.

## How the 6 were made lookaround-free (and kept byte-identical)

Two techniques, both DFA-compatible:

1. **Boundary assertion → one-character class check in code**, using the *exact*
   original class semantics. Critically, Python's `\d`/`\w` are Unicode-aware
   (`٩` U+0669 is a `\d`), so the check compiles `re.compile(r"[\d-]")` etc.
   rather than ASCII string membership — ASCII membership under-restricts and
   diverges on non-ASCII input, the same Unicode trap that disqualified re2
   (`docs/PERFORMANCE_BACKENDS.md`). The differential test caught exactly this on
   `123-45-6789٩`. Rust's `regex` uses Unicode `\d`/`\w`, matching Python.
2. **Positive lookbehind → folded into the regex.** Anthropic/OpenAI's
   `[A-Za-z0-9_-]{20,}(?<=[A-Za-z0-9_])` (last char must be a word char, not a
   trailing `-`) becomes `[A-Za-z0-9_-]{19,}[A-Za-z0-9_]` — still ≥20 chars,
   last is a word char, no lookbehind, and the engine does the backtracking the
   original did. (A plain `\b` candidate is *not* equivalent — it wrongly allows a
   trailing `-` before a Unicode word char; the differential test caught this on
   `sk-ant-…文`.)

The equivalence bar is absolute and enforced: `LookaroundFreeDetector.detect(x)`
== `DeterministicDetector.detect(x)` (span, text, type, confidence) for the
covered types, on the corpus and under Hypothesis fuzzing that includes
adversarial adjacency and Unicode. A pattern that diverges does not ship — same
rule as re2.

## credit_card and phone — the scanner cases

Both use a greedy, variable-length core whose alphabet includes separators
(`\d[ -]?`, digit groups with ` .-`), guarded by a negative lookahead. When the
lookahead fails at the greedy end, the regex engine **backtracks to a shorter
match**; a lookaround-free candidate scanned with `finditer` + post-filter
consumes the greedy span and cannot recover the shorter valid match. This is
intrinsic, not a tuning issue — so they are not forced into the `RegexSet`.

Two candidate native implementations, both gated by the same differential test:

- **`fancy-regex` (Rust) for these two only** — *built, measured, and rejected*
  (see "Sub-step (a)" below). `fancy-regex` supports lookaround/backtracking, so the
  patterns port verbatim; but it is a backtracking engine like CPython's `re`, not
  faster than it, and its backtrack limit makes it either under-detect (truncates)
  or catastrophically backtrack on dense digit input. Not viable.
- **Hand-rolled linear state machine** — the remaining path. Scan for a start (digit
  not preceded by `[\d-]`), greedily consume the core counting digits, then apply the
  trailing boundary with explicit trim-back of trailing groups until the lookahead
  holds or the minimum length is violated; then Luhn / `phone_ok`. More code, but
  linear-time with no backtracking (so no truncation and no DoS surface). Must pass
  the differential+fuzz gate before shipping. This is now the only route to a native
  credit_card/phone; until it exists, they stay in Python.

## Native core plan (step 3, gated)

1. `[native]` optional extra + `backend="native"` on the deterministic tier;
   pure-Python stays the default and the byte-identical oracle/fallback.
2. Rust crate (PyO3 + maturin): per-pattern `regex` `find_iter` with SIMD literal
   prefilters for the DFA-ready patterns (a `RegexSet` was measured and rejected —
   see "Step 3 — first native slice") → a `fancy-regex` slow lane was *planned* for
   credit_card/phone but **built and rejected** (Sub-step (a)); they stay in Python →
   return spans to the existing Python arbitration + policy (move those into Rust
   later only if profiling says so). *This is the original plan; the measured
   sub-steps below supersede it where they differ.*
3. Ship only when a differential test proves `native.detect(x) == python.detect(x)`
   byte-for-byte across the corpus + fuzzed Unicode, and the baseline harness
   (`docs/BASELINE.md`) shows a real, measured speedup. Report numbers; if it
   diverges or doesn't help, it does not ship (the re2 precedent).

## Step 3 — first native slice (built and measured)

The crate lives in `native/` (PyO3 + `regex`, built with maturin to an **abi3**
wheel — one wheel per platform for CPython ≥ 3.10, keeping the build matrix
small). The first slice implements the 12 lookaround-free, group-0, no-validator
credential patterns and exposes `detect(text) -> [(char_start, char_end, type,
confidence)]`.

Two findings, both measured:

1. **`RegexSet` is the wrong tool here.** A combined automaton is bloated by
   `private_key`'s `{1,8100}` bound and does not use each pattern's required-
   literal prefilter — it measured **~6 MB/s**. Running each pattern as an
   individual `Regex` with `find_iter` lets the crate's built-in memchr/
   aho-corasick literal prefilter (SIMD) engage — the automatic analogue of the
   Python anchor prefilter — at **400–1200 MB/s**. The core uses individual
   `find_iter`.
2. **Byte→char offset conversion matters.** Rust `regex` yields *byte* offsets;
   Python `Detection` uses *character* offsets. The core converts them (ASCII fast
   path; otherwise a single O(n+matches) pass), so output is byte-identical on
   non-ASCII input — verified on `文字a@b.io文字` etc.

Measured vs the Python tier on the **same 12 patterns** (5 MB corpus, best of 3,
`benchmarks/native_backend.py`; absolute numbers are environment-dependent, the
ratio is the result):

| Corpus | Python | Native | Speedup |
| --- | --- | --- | --- |
| none (0% PII)   | 163 MB/s | 1195 MB/s | **7.3×** |
| sparse (1% PII) |  25 MB/s | 1229 MB/s | **48.8×** |
| dense (50% PII) |  23 MB/s |  376 MB/s | **16.6×** |

Output is **byte-identical** to Python (span/type/confidence, incl. Unicode char
offsets), gated by `tests/test_native_backend.py` (corpus + Hypothesis fuzz;
skips when the native extra isn't installed, so default CI stays green) and by a
source-equality check (`patterns()` must match the Python pattern strings).

Note this slice is the *conservative* case: these credential patterns are already
cheap in Python (anchor prefilter), yet native still wins 7–49×.

### Sub-step 1 — SSN (first digit-gated PII pattern, the real bottleneck)

SSN is the representative bottleneck pattern: `\d{3}-\d{2}-\d{4}` has **no
distinctive literal**, so Python cannot prefilter-skip it — its regex runs on
*every digit-bearing line*. Ported as a lookaround-free candidate + a
Unicode-aware boundary check (`[\d-]` neighbours, using Rust's Unicode `\d` to
match Python) + the `ssn_ok` validator. The validator is **pure string
comparison** (`split('-')`, `starts_with('9')`, `!= "00"`), so it is byte-identical
to Python *including Unicode-digit SSNs* — no `int()` involved.

Measured (5 MB, best of 3; distractor lines carry digits so Python must run the
SSN regex on each):

| SSN density | Python | Native | Speedup |
| --- | --- | --- | --- |
| 0% (digit distractors only) | 35 MB/s | 413 MB/s | **11.8×** |
| 10% | 32 MB/s | 350 MB/s | **11.7×** |
| 50% | 23 MB/s | 209 MB/s | **9.0×** |

Byte-identical to Python, gated by the differential test + a 30 000-example
Hypothesis fuzz stressing SSN boundaries and Unicode digits (0 divergences).

### Sub-step 1b — IPv4/IPv6, and the Unicode-`int()` parity (solved)

Python detects **Unicode-digit** IPv4 too (`٩٩.٩.٩.٩` → ipv4), because `ipv4_ok`
calls `int(octet)` and Python's `int()` accepts any Unicode decimal digit, while
Rust's `str::parse`/`char::to_digit` are ASCII-only. Solved with a complete
Unicode digit-value function: every `Nd` character is one of **76 contiguous
10-codepoint blocks**, so its value is `codepoint − block_zero`; the 76 block
"zeros" are embedded as a table and `octet_value` folds digit values exactly as
`int()` does (mixed scripts included: `int("٩5") == 95`). Completeness is
**proven, not sampled**: a test asserts native digit value == Python `int()` for
**every** Unicode `Nd` codepoint (0 mismatches over all 660). IPv6's candidate is
ASCII hex + colons only, so it has no Unicode-digit case — its validator is
`Ipv6Addr::from_str`, verified against Python `ipaddress` by the fuzz.

Measured on the same-pattern-set corpus (5 MB, best of 3), now with SSN + IPv4 +
IPv6 all active (each digit-gated, so Python must run all three per digit-bearing
line — the compounding bottleneck):

| PII density | Python | Native | Speedup |
| --- | --- | --- | --- |
| 0% (digit distractors only) | 10 MB/s | 264 MB/s | **25.3×** |
| 1% | 7 MB/s | 243 MB/s | **33.4×** |
| 50% | 7 MB/s | 151 MB/s | **21.9×** |

Byte-identical, gated by the differential test + a 40 000-example fuzz over IPv4/
IPv6 edge cases (invalid octets, leading zeros, `::`, over-long, Unicode digits;
0 divergences). `credit_card`/`phone` were the intended slow-lane cases — see
Sub-step (a), where `fancy-regex` was built and rejected.

### Sub-step 2 — wired into the pipeline (`backend="native"`, end-to-end measured)

The native core is now selectable through the public API:
`Redactor(..., backend="native")` (also `"auto"`), forwarded to
`DeterministicDetector(backend=...)`. The deterministic tier runs a **hybrid**:
the 15 types the core covers go through Rust (`_detect_native`), the remaining 8
(`credit_card`, two `phone` patterns, and the label-gated
`aws_secret`/`api_key`/`url_credentials`/`anthropic_key`/`openai_key`) stay in
Python (`_detect_python`). The combined output is byte-identical to
`backend="python"` — a differential gate (`tests/test_native_backend.py`:
`test_backend_equivalence_*`) asserts full-detector equality (span, text, type,
confidence, source) on the corpus and under Hypothesis fuzz that mixes native-lane
and Python-lane specimens. The extension is optional: `"native"` warns and falls
back to pure Python when it isn't installed, `"auto"` falls back silently, so the
package stays dependency-free.

**End-to-end redaction throughput** — the honest, whole-pipeline number, not the
detect-loop microbenchmark. Real `redact_file` (read → decode → all detector tiers
→ arbitration → policy → write), 10 MB, `load_plugins=False`, best of two runs
(`benchmarks/baseline.py --backends python native`):

| Density | Python | Native | Speedup | Detections (py = native) |
| --- | --- | --- | --- | --- |
| none (0%)    | 3.40 MB/s | 5.49 MB/s | **1.6×** | 0 |
| low (1%)     | 2.74 MB/s | 4.30 MB/s | **1.6×** | 929 |
| medium (10%) | 2.46 MB/s | 4.06 MB/s | **1.7×** | 10 202 |
| high (50%)   | 2.07 MB/s | 2.96 MB/s | **1.4×** | 69 594 |

Why only **1.4–1.7×** end-to-end when the same-pattern-set detect loop is 21–33×
faster (sub-step 1b)? Two reasons, both measured in the tier profile below:

1. The 1b microbenchmark ran **only the 15 native-covered types**. The full
   deterministic tier also runs `credit_card` and two `phone` patterns — digit-gated,
   expensive, and **still Python in the hybrid** (the `fancy-regex` slow lane meant to
   move them was built and rejected — Sub-step (a)). On the realistic corpus they
   dominate the tier: dropping them takes the
   native deterministic tier from **10.5 → 128 MB/s** at 0% density. So the native
   hybrid's deterministic tier is only ~2× faster than Python end-to-end, not 25×,
   because it still pays the Python `credit_card`/`phone` cost on every digit line.
2. The other tiers and the read/decode/arbitration/policy/replace/write path are
   Python too — an Amdahl ceiling. The gain shrinks as density rises (1.7× → 1.4×)
   as more matches shift work into the still-Python replace/arbitration path.

The remaining headroom is therefore **`credit_card`/`phone`**, not the entropy tier
(see the profile).

The native build also raises RSS ~20 MB → ~43 MB (the compiled regex automata),
a fixed cost independent of input size — the constant-memory invariant is
unchanged (still flat across file size), the floor is just higher.

### Evaluation — should the entropy tier be ported next? (measured: no)

Profiled per tier on the same 10 MB corpora (standalone `detect()` throughput, and
the end-to-end effect of turning the tier off), to decide where the next native
port should go. Higher MB/s = faster:

| Tier (native backend) | 0% | 1% | 10% | 50% |
| --- | --- | --- | --- | --- |
| deterministic (hybrid) | 10.0 | 7.2 | 6.9 | 6.5 |
| **entropy** | **52.9** | **52.4** | **45.4** | **21.7** |
| contextual | 42.4 | 41.4 | 41.2 | 42.0 |

The entropy tier is **already the fastest tier** — 3–8× faster than the
deterministic tier it would sit beside. Its end-to-end share (measured as the delta
from `use_entropy=False`, so it also captures the arbitration it saves) is only
**10–21%**, an absolute ceiling of **1.11–1.27×** *if the port were free*:

| Density | native+entropy | native, no entropy | entropy share | ceiling |
| --- | --- | --- | --- | --- |
| none | 5.48 MB/s | 6.49 MB/s | 15.6% | 1.18× |
| low | 4.51 MB/s | 5.04 MB/s | 10.5% | 1.12× |
| medium | 4.12 MB/s | 4.59 MB/s | 10.3% | 1.11× |
| high | 3.07 MB/s | 3.89 MB/s | 21.2% | 1.27× |

Against that thin ceiling, a port carries a **byte-identity hazard worse than any
pattern shipped so far**. The classifier is `shannon_entropy(token) >= 4.0` (base64)
or `>= 3.0` (hex), where entropy is `-Σ (c/n)·log2(c/n)` in float64. Reproducing it
in Rust needs `f64::log2` and the same summation order to agree with CPython's
`math.log2` to the last ULP; a token whose true entropy sits within ~1e-12 of a
threshold could flip classes across the two libm implementations (and platforms).
Unlike the Unicode-`int()` case — exact integer arithmetic, provable complete — this
is floating-point equality that cannot be *guaranteed* bit-identical, only tested.
The `meta={"entropy": f"{…:.2f}"}` string stacks a second float-formatting parity
requirement on top. High risk, ≤1.27× reward.

**Recommendation: do not port the entropy tier now.** The correct next target is
`credit_card`/`phone` — ~90% of the deterministic tier's cost on real input (10.5 →
128 MB/s when removed). Revisit entropy only if a later step moves the whole
detection pass into one native scan (where the entropy candidate scan amortizes into
a pass already being made, and the float comparison is the only new risk); as a
standalone port it is the wrong tier.

### Sub-step (a) — credit_card/phone via `fancy-regex`: built, measured, **rejected**

The slow lane was implemented in full: `fancy-regex` 0.19, the three patterns
(credit_card + two phone) ported verbatim with the lookaround intact, Luhn/`phone_ok`
validators reproduced (Luhn reuses the proven Unicode `digit_value`; `phone_ok`'s
`strip()` is a no-op on any match, so the date/SSN-shape rejections and the 7–15
digit-count run on the match directly). In isolation it was byte-identical — the
corpus and a 40 000-example fuzz over card/phone edge cases (separators, Unicode-digit
cards, date/SSN-shape rejection) passed with **0 divergences**. It still does not
ship, for two independent, measured reasons:

1. **Correctness — silent under-detection (fail-open).** On the 10 MB baseline corpus
   the native `credit_card` scan **truncated at offset ~1.6 MB, finding 18 of 123
   cards** the Python tier finds. `fancy-regex`'s `find_iter` hit its backtrack limit
   on the digit-dense distractor lines and returned an error mid-scan, so every card
   past that point was missed. For a redaction tool a missed secret is the worst
   failure mode — and it slipped past the isolated corpus/fuzz tests, surfacing only
   on multi-MB input. Raising the limit to 10⁹ made it byte-identical again but…
2. **Performance — no gain, plus a DoS surface.** With the limit raised enough to be
   correct, the native deterministic tier measured **0.89× at 0 % density and
   1.03–1.05×** at 1–50 % — i.e. break-even to *slightly slower* than pure Python.
   `fancy-regex` is a backtracking engine like CPython's `re`; it does not backtrack
   *faster* than a mature C engine, so there is nothing to win here. The apparent
   "48× at 0 %" seen before raising the limit was the truncation bug — fast because
   it was doing less work and under-detecting. Worse, a 10⁹-step backtrack budget
   reintroduces the catastrophic-backtracking DoS surface that earlier phases
   deliberately bounded (the `private_key` length cap, assumption A1) — unacceptable
   for a tool that processes untrusted input.

Byte-identical but **not faster** (and correct only with a limit that is itself a
liability) fails the shipping bar (ship only if faster *and* identical — the re2
precedent). The port was reverted; `credit_card`/`phone` stay in Python. The only
route left to a native version is the **hand-rolled linear scanner** above: linear
time, no backtracking, no truncation, no DoS surface — the extra code buys the one
thing `fancy-regex` structurally cannot give. Whether it beats CPython's C `re`
enough to matter (Python `re` already does ~11 MB/s for the trio) is itself an open,
benchmark-gated question before that work is worth starting.

## 0.5 — exact Unicode parity, the whole deterministic tier, hardening

### A parity bug: `\w` is not the same word class in Rust and CPython

Fuzzing with characters the earlier gate never generated found the native core
**missing secrets the Python tier redacts**: `AKIAIOSFODNN7EXAMPLE` followed by a
combining acute accent (U+0301) or a zero-width non-joiner, `a@b.io` followed by a
zero-width joiner, `2001:db8::1` before a combining mark, an npm token before `‿`.
7 of 8 probes diverged, mostly in the leaking direction. The cause is the word class
behind `\b` and `\w`: CPython uses `str.isalnum()` or `_`; Rust's `regex` uses
Alphabetic + marks + Nd + connector punctuation + Join_Control. Combining marks,
ZWJ/ZWNJ and `‿` are word characters to Rust only (so `\b` fails after the key and
nothing matches); `²`/`½` are word characters to CPython only. Two smaller cases
of the same kind: CPython's `\s` also matches `\x1c`–`\x1f`, and under
`IGNORECASE` CPython lower-cases (`İ` matches `i`) where Rust case-folds. And each
CPython ships its own Unicode version (3.10: 13.0 … 3.14: 16.0), so `\d` differs
on newly added digits.

The fix is exact rather than approximate. `native/tools/gen_unicode_tables.py`
dumps how the locked `regex` crate and **every supported CPython** classify all
1.1M code points (`\w`, `\d`, `\s`, and case-insensitive ASCII letters) and
writes `native/src/unicode_tables.rs`: the code points on which any of them
disagree (13 454 for `\w`, 110 for `\d`, 2 for case folding, none for non-ASCII
`\s`). Everywhere else the engines agree, which the Python test
`test_unambiguous_code_points_classify_exactly_like_cpython` re-verifies on the
interpreter under test (0 mismatches on 3.10, 3.11, 3.12, 3.13 and 3.14). Before a
scan, `needs_python` checks the text: an ambiguous digit or case-folding code point
anywhere, or an ambiguous word character next to something a pattern consumes,
makes the core return `None`, and the caller runs the Python tier on that text.
All-ASCII text skips the check, and a combining mark inside Devanagari or Thai
text, away from anything a pattern consumes, does not trigger it. `\x1c`–`\x1f`
are added to the compiled `\s` explicitly.

### Everything in the deterministic tier is native now

| Patterns | Engine |
| --- | --- |
| 12 credential patterns, anthropic/openai keys | `regex` `find_iter` with SIMD literal prefilters |
| ssn, ipv4, ipv6 | lookaround-free candidate + boundary check + validator |
| url_credentials, api_key, aws_secret | `regex` captures (group 1); aws_secret's case-insensitive `(?![A-Za-z0-9/+])` re-checked in code, including `ſ` and the Kelvin sign that CPython's `IGNORECASE` folds into it |
| credit_card, 2 × phone | hand-written linear scanners (`native/src/digits.rs`) |
| 6 labeled-identifier rules | `regex` captures, `(?i)` cue alternations as literal prefilters |

**The linear scanners** finish the job `fancy-regex` could not (Sub-step (a)). Each
regex is transcribed into code that explores alternatives in CPython's priority
order: greedy quantifiers longest first, `?` taking first, alternation left first.
A match is bounded (card ≤ 37 characters, phone ≤ 36), so all work for one start
position happens in a 48-character stack window, and the phone repetitions are
memoised on (position, iteration). That makes the scan linear with no
backtracking blow-up, and with no backtrack limit that could truncate. Each pattern
resumes after its own last match, as `re.finditer` does, and Luhn / `phone_ok` run
after matching, as in Python. Candidate starts are found 8 bytes at a time (a
branch-free SWAR test for digits, `+`, `(` or a non-ASCII byte, in safe Rust), and
the rest of a digit run is skipped once its first digit has been tried.

The gates: the 1.1M-code-point class check; corpora of card/phone/label edge cases;
Hypothesis generators built to hit the regexes' corners (Luhn-valid 12–21 digit
numbers with per-digit separators, 3–6 digit groups with `+`/`(…)` prefixes and
lookahead-breaking suffixes; 667 of 3 000 examples produce matches); a native vs
Python streaming test over arbitrary chunk cuts; and a mutation check (two planted
scanner bugs, both caught, one shrunk to `'0000000000000 4'`).

### Measured

Rust, Criterion, 4 MiB synthetic logs (`cargo bench --no-default-features`; this
sandbox's numbers vary ±15 % between runs):

| Benchmark | 0 % PII | 50 % PII |
| --- | --- | --- |
| `scan/whole` (all native patterns) | ~140 MiB/s | ~120 MiB/s |
| `scan/regex_only` | ~300 MiB/s | ~220 MiB/s |
| `scan/digits_only` (card + phone) | ~270 MiB/s | ~260 MiB/s |
| `scan/windows` (64 KiB chunks + 8 KiB overlap) | ~90 MiB/s | ~85 MiB/s |
| `scan/labeled` | ~145 MiB/s | ~120 MiB/s |
| memory-bandwidth floor (count newlines) | ~2.1 GiB/s | ~2.1 GiB/s |

The digit scanners went from 167 to ~270 MiB/s with the SWAR prefilter and run
skipping. Within the regex half, SSN (520 MiB/s) and IPv6 (2 GiB/s) cost the most:
they have no literal prefix, so the DFA reads every byte. The other 13 patterns run
at 9–31 GiB/s. A dedicated SSN scanner is the next native win, but the native scan
is now a small slice of the pipeline.

Python, per tier (`detect` on 64 KiB windows, 4 MB, 1 % PII):

| Tier | Python | Native | Speedup |
| --- | --- | --- | --- |
| deterministic | 4.4 MB/s | 114 MB/s | 26× |
| labeled_identifier | 4.3 MB/s | 154 MB/s | 36× |
| full `Redactor.detect` | 1.9 MB/s | 15.9 MB/s | 8.4× |

End to end, `benchmarks/baseline.py --backends python native` (real
`redact_file`, 10 MB, one worker; detection counts identical in every row):

| Density | Python | Native before | Native now | vs Python | vs native before |
| --- | --- | --- | --- | --- | --- |
| none | 1.62 MB/s | 1.92 MB/s | 13.59 MB/s | 8.4× | 7.1× |
| low (1 %) | 1.52 MB/s | 1.75 MB/s | 11.70 MB/s | 7.7× | 6.7× |
| medium (10 %) | 1.43 MB/s | 1.60 MB/s | 9.45 MB/s | 6.6× | 5.9× |
| high (50 %) | 1.19 MB/s | 1.44 MB/s | 5.25 MB/s | 4.4× | 3.6× |

What is left is Python: the entropy and contextual tiers (~45–53 MB/s each), and
building one `Detection` object per match, arbitration and replacement, which is
why the gain shrinks as density rises. Peak RSS is 42.5 MB (pure Python: 22 MB).

### Hardening

* **No panics in production code.** The crate denies `unwrap`, `expect` and
  `panic!` outside tests (clippy); pattern compilation returns an `Error` that the
  bindings raise as `RuntimeError` at import, where the Python side falls back.
* **Bounded memory.** Every regex is built with explicit `size_limit` (16 MiB) and
  `dfa_size_limit` (4 MiB) caps. Output buffers grow with `try_reserve`, so under
  an `RLIMIT_AS` cap a scan that cannot allocate raises `MemoryError` (the CLI's
  exit 3) instead of aborting; `test_output_buffer_exhaustion_raises_memory_error_not_abort`
  checks this in a child process. **Limit:** allocations *inside* the `regex`
  crate (its lazy-DFA cache grows during a scan) cannot be made fallible on stable
  Rust, and with under ~2 MB of headroom one aborts the process. The memory budget
  therefore reserves `NATIVE_PER_WORKER` (32 MiB, against ~20 MB measured) per
  worker when the native core is active.
* **No allocation in the scan loops** beyond the output buffer: card/phone windows
  and memo tables live on the stack, byte-to-character offsets are converted with a
  reusable sorted table (no per-call `HashMap`), and the bindings keep per-thread
  scratch buffers.
* **Pure-Rust build.** `cargo build --no-default-features` has no PyO3 in its
  dependency graph (`regex`, `regex-syntax`, `aho-corasick`, `memchr` only); CI
  asserts it. Rust callers reuse the output `Vec` across calls.

### What the requested optimizations do and don't buy

* **SIMD multi-pattern matching** already happens: `regex` builds memchr/Teddy
  (SSE2/AVX2/NEON) literal prefilters per pattern. A single `RegexSet` or one
  Aho-Corasick automaton over all patterns was measured before and loses the
  per-pattern prefilters (~6 MB/s). SIMD in the digit scanners is SWAR in safe
  Rust, not `unsafe` intrinsics.
* **SIMD Luhn** would not help: Luhn runs once per candidate match on at most 19
  digits, after matching, and never shows in the profile.
* **Chunk-boundary splits** are handled by the streaming engine's overlap (8 KiB by
  default, larger than any native match); the property test `chunk_cuts_preserve_every_match`
  replays the engine's window logic over arbitrary chunk sizes. One inherent limit
  carries over from the Python tier: card/phone matching is chained like
  `re.finditer`, so an *unbroken* run of digits and spaces longer than the overlap
  could be segmented differently mid-run. Real text breaks such runs.

## 0.5 (cont.) — every default tier is native

Earlier sections declined to port the entropy tier because its threshold is a
floating-point comparison that cannot be guaranteed bit-identical. It is now ported
**exactly**, by handling the float the same way the Unicode classes were handled:
decide natively only where both engines must agree, and hand the rest to Python.

* **Entropy and compound secrets** (`native/src/secrets.rs`). Candidate runs, the
  letters-only / hex / length / class-diversity / distinct-ratio gates are integer
  and ASCII logic, identical by construction (the distinct ratio is an
  integer-over-integer IEEE division in both). Shannon entropy is computed from a
  stack histogram. For these tokens (at most 66 distinct ASCII characters, at most
  `MAX_SPAN` long) any faithful `log2` and either summation — CPython 3.12+ uses
  Neumaier-compensated `sum()`, 3.10/3.11 a naive one — land within ~1e-13 of the
  true value. So a token whose native entropy is more than **1e-9** from its
  threshold gets the same verdict in Python, and one more than 1e-6 hundredths from a
  rounding boundary gets the same `meta["entropy"]` string. Tokens inside either band
  come back *undecided* and Python classifies and formats them itself. They are
  rare but real: 16 distinct characters used equally is exactly 4.0 bits, the
  base64 threshold (`test_entropy_on_the_threshold_is_decided_in_python`).
* **Contextual tier** (`native/src/context.rs`). Bare-SSN detection is a digit-run
  scan. `adjust` returns only the boost/suppress *decisions*; the confidence
  arithmetic stays in Python, so the floats are Python's own. Trigger words are
  matched against `str.lower()` of the window. All triggers are ASCII, and on every
  supported CPython exactly two non-ASCII characters lower-case to ASCII (pinned by a
  test): the Kelvin sign (to `k`, mapped natively) and `İ` (to `i` + combining dot,
  sent to Python). Native `adjust` is used only for detections from built-in tiers,
  whose `text` is exactly the span, since a plugin's detection might not be.
* **Pickling.** A native-backed detector held the extension module and could not be
  pickled, so `--workers N` with the native backend failed wherever the parallel
  engine pickles (the `spawn`/`forkserver` start methods: macOS, Windows, Python 3.14
  on Linux). Detectors now pickle their backend name and reload the module.

The full-pipeline differential test (`test_full_pipeline_matches_python_fuzzed`)
compares every detection's span, text, type, exact confidence, source and `meta`
against `backend="python"` on the whole default pipeline. Two planted bugs (drop the
Kelvin mapping; hex minimum 32 → 31) both fail it.

Per stage, 4 MB on 64 KiB windows (native backend):

| Density | Before (det + labeled native) | Now (all tiers native) |
| --- | --- | --- |
| none | 13.1 MB/s (contextual 43 %, entropy 31 %) | 44.2 MB/s |
| medium | 12.0 MB/s | 28.2 MB/s |
| high | 6.5 MB/s (adjust 18 %) | 12.6 MB/s |

What remains at high density is per-detection Python work: building `Detection`
objects, `resolve_overlaps`, and the policy's replacement.

Criterion (4 MiB, `cargo bench --no-default-features`): `scan/entropy` ~530 MiB/s at
0 % PII and ~400 MiB/s at 50 %; `scan/compound` ~960 / ~870 MiB/s (the Python tiers:
~45-53 MB/s).

### 200 MB, one and four workers

`benchmarks/baseline.py --sizes 200 --densities low high --workers 1 4 --backends
python native` (real `redact_file`: read, decode, every tier, arbitration, policy,
write; 4 vCPU). Detection counts are identical in every Python/native pair (18 579
at low density, 1 367 479 at high):

| Density | Workers | Python | Native | Speedup |
| --- | --- | --- | --- | --- |
| low (1 %) | 1 | 1.31 MB/s | 34.5 MB/s | 26x |
| low (1 %) | 4 | 5.17 MB/s | 120.7 MB/s | 23x |
| high (50 %) | 1 | 1.12 MB/s | 10.4 MB/s | 9.3x |
| high (50 %) | 4 | 2.14 MB/s | 36.5 MB/s | 17x |

Memory stays flat over 200 MB: 42.8 MB RSS for the parent and 36-38 MB per worker
with the native core (Python: 23-25 MB and 18-20 MB).

### E.164 country codes

`phone_ok` (Python and native alike) now requires an assigned E.164 country code
for a `+` number: the 215 codes in libphonenumber's metadata, a prefix code. A
separated 1–3 digit group (`+44 20 …`) must be a code exactly; an unbroken run
(`+14155552671`) must begin with one; no code starts with 0. The native table is a
1000-bit set built at compile time (one shift and mask per lookup). On RedactionBench
it removes the only `+` false positive (a `+0000` timezone offset in a `date` line)
and loses no gold phone; the synthetic generators, which drew invented codes like
`+13` and `+25`, now draw real ones.

## Unicode word boundaries on non-ASCII text

The `regex` crate's lazy DFA cannot evaluate a Unicode `` once it reads a
non-ASCII byte; the search then falls back to a much slower engine for the rest
of the haystack. Sixteen patterns and every label-anchored rule use ``, so a
single accented name or curly quote in a 64 KiB window made the whole window
10-20x slower. A synthetic corpus with a few accented names per window ran the
full native `detect` at 1.7 MB/s.

`patterns::WordBounded` keeps the exact semantics and the speed. On ASCII text,
or for a pattern without ``, it scans as before. Otherwise a *relaxed* copy of
the pattern with every `` removed (its match starts are a superset of the
exact pattern's, and it has nothing the DFA must give up on) finds candidate
starts at DFA speed, and the exact pattern verifies each one with an *anchored*
search (`regex-automata`), which costs only the candidate's length. Candidates
are tried left to right and the scan resumes after each match, which is
`captures_iter`'s leftmost-first order. After 64 rejected candidates in one
window the scan finishes with the exact regex's own linear-time search, so
hostile input (a 60K-character word run glued to an accented letter, before an
`@`) stays linear; `tests/test_recall_vectors.py` times it.

Same corpus, 64 KiB windows, after the change (byte-identical output, checked by
the differential tests plus glued-Unicode corpus lines and a 1,500-example fuzz):

| Tier | Before | After |
| --- | --- | --- |
| deterministic | 11.5 MB/s | 37.0 MB/s |
| labeled_identifier | 4.9 MB/s | 85.5 MB/s |
| full `Redactor.detect` | 1.7 MB/s | 14.7 MB/s |

## Status

- Step 2 (`detectors/_lookaround_free.py` + `tests/test_lookaround_free.py`):
  **done** — 19/21 patterns DFA-ready with a proven byte-identical rewrite.
- Step 3 scaffold + sub-steps 1/1b (`native/`, `benchmarks/native_backend.py`,
  `tests/test_native_backend.py`): **done** — toolchain validated; 12 credential
  patterns + SSN + IPv4 + IPv6 are byte-identical and 9–49× faster (21–33× on the
  digit-gated PII bottleneck); Unicode-`int()` parity proven complete. The
  extension is optional and built-from-source only.
- Sub-step 2 — wiring (`Redactor(backend=...)` → `DeterministicDetector`): **done**
  — hybrid native/Python deterministic tier, byte-identical to `backend="python"`
  end-to-end (differential + fuzz gate), graceful fallback when the extension is
  absent (`"native"` warns, `"auto"` silent). Measured whole-pipeline redaction
  gain **1.4–1.7×** (Amdahl-limited by the still-Python entropy/contextual tiers
  and the arbitration/replace path — see sub-step 2 above).
- Sub-step (a) — credit_card/phone via `fancy-regex` **built and rejected** (see the
  evaluation above). Byte-identical in isolation but under-detected on multi-MB input
  (backtrack-limit truncation, a fail-open miss) and, once made correct, was
  break-even to slightly slower with a catastrophic-backtracking DoS surface.
  Reverted; they stay in Python. A hand-rolled linear scanner is the only route left,
  and is itself benchmark-gated (Python `re` already does ~11 MB/s for the trio).
- Sub-step (b) — entropy-tier port **evaluated: declined** (see the evaluation
  above). It is already the fastest tier (3–8× the deterministic tier); end-to-end
  ceiling ≤1.27×, against a floating-point `log2` byte-identity hazard that cannot be
  proven bit-identical the way the integer cases were. Left in Python.
- Sub-step (c) — packaging: **done**. `pyproject.toml` gains a `[native]` extra
  (`pip install safestream-redactor[native]`) depending on the separately-published
  `safestream-redactor-native` wheel; `.github/workflows/native-wheels.yml` builds
  abi3 wheels across Linux (x86_64, aarch64), macOS (Intel, Apple Silicon) and
  Windows (one wheel per platform, since abi3 spans CPython ≥ 3.10) plus an sdist,
  and publishes them to PyPI via Trusted Publishing on a `native-v*` tag. The native
  crate is version-locked to the package (`native/Cargo.toml` → 0.4.0), and a
  runtime **spec-guard** (`_native_matches_spec`) falls back to pure Python with a
  warning if a version-skewed wheel is ever paired — so a mismatched wheel degrades
  safely instead of diverging.
- 0.5: the hand-rolled linear credit_card/phone scanner was built and ships, as do
  the label-gated credentials and the labeled-identifier tier; a Unicode parity bug
  (Rust vs CPython `\w`) was found and fixed exactly; see the 0.5 section above.
  The entropy tier stays in Python (the float `log2` hazard above still holds).
- Maintainer to-do before the first publish (one-time, external to the repo): create
  the `safestream-redactor-native` project on PyPI (and TestPyPI) and add a GitHub
  Trusted Publisher for workflow `native-wheels.yml` with environment `pypi-native`
  (`testpypi-native` on TestPyPI) — as documented in the workflow header.
