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
  the differential+fuzz gate before shipping. **Built and shipped** — see
  "Sub-step (d)" below.

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

*Superseded:* the port was later built, with the float-parity hazard resolved by
reproducing the arithmetic exactly. See "Sub-step (e)" below.

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

### Sub-step (d) — credit_card/phone as hand-rolled scanners: built, measured, **shipped**

`native/src/structured.rs` implements the three patterns as scanners that reproduce
`re.finditer` for the exact Python regex: the same start positions, the same
depth-first order over quantifier choices (greedy = longest first, optional =
present first), and the same lookarounds with Python's character classes.

- **credit_card** reduces to a closed form. The optional `[ -]?` is always taken
  when present (skipping it leaves a separator where the next `\d` must be), so a
  candidate is a chain of digits, each optionally followed by one separator. The
  only real choice is the digit count t ∈ 13..19, and greedy-then-backtrack keeps
  the largest t whose next character passes `(?![\d-])`. That is at most 19 checks
  per start.
- **structured phone** has real choices: optional separators let a digit run
  split many ways. The depth-first search is memoised on (position, groups so far).
  Whether the rest of the pattern matches from a state does not depend on the path
  that reached it, so memoising never changes which match is found first. Work per
  start is bounded by states × choices, not by paths.
- **bare phone** has mandatory separators, so its search tree is narrow and needs
  no memo.

Validators: Luhn reuses the proven Unicode `digit_value`; `phone_ok` reproduces the
`strip()`, the ISO-date and SSN shape rejections, and the 7–15 digit count.

**Gates passed** (the bar that `fancy-regex` failed):

| Check | Result |
| --- | --- |
| `tests/test_native_backend.py`: corpus, 500-example fragment fuzz, 3 000-example character-level scanner fuzz, wired-detector fuzz | identical, on Python 3.11, 3.12 and 3.14 |
| Ad-hoc differential: 2 000 000 random and structured cases (~76 k card, ~98 k structured-phone, ~89 k bare-phone matches) | **0 divergences** |
| `benchmarks/baseline.py` corpora, 10 MB × 4 densities: deterministic tier and full `Redactor.redact` output | identical; **123/123** cards on the "low" corpus where `fancy-regex` found 18 |
| Adversarial 4 MB inputs (all digits, `1 1 1…`, `1-1-1…`, `+` + 30 digits, nested `(12)12.12…`, back-to-back 20-digit cards) | identical and linear: 7–102 MB/s native vs 0.7–10 MB/s Python |

**Measured** (`benchmarks/native_backend.py`, 5 MB, best of 3, same container,
before = `main`'s native core, after = this change):

| Corpus | `backend="python"` | native before | native after |
| --- | --- | --- | --- |
| none (0 % PII) | 5.0 MB/s | 10.2 MB/s (2.0×) | **55.1 MB/s (11.2×)** |
| sparse (1 %) | 3.7 MB/s | 6.7 MB/s (1.8×) | **15.8 MB/s (4.3×)** |
| dense (50 %) | 3.6 MB/s | 5.9 MB/s (1.7×) | **13.5 MB/s (3.9×)** |

That is the whole deterministic tier as users run it. The remaining Python cost
is the five label-gated credential patterns (anthropic/openai keys, URL
credentials, AWS secret, api_key). Whole-pipeline `Redactor.redact` goes from
1.1–1.3× to **1.6×** over pure Python. The entropy and contextual tiers, both
still Python, now bound it (see sub-step (b)).

### Python character classes in the native core (a latent divergence, fixed)

The regex lane used the `regex` crate's own `\w`, `\b` and `\s`, which are not
Python's. Python's `\w` is `str.isalnum() or "_"`: it includes No numerics such as
`²`, and excludes combining marks and connector punctuation other than `_`. Rust
follows UTS#18, which is the reverse on both counts. Python's `\s` (`str.isspace()`)
includes `\x1c`–`\x1f`, and Unicode White_Space does not. The existing tests never
put such a character next to a token, so the shipped core diverged in both
directions. It **missed** `‿AKIAIOSFODNN7EXAMPLE`, `\u0301bob@x.io`, `\u0301::1`
and a PEM body containing `\x1c`, and it over-detected `²bob@x.io` and
`²2001:db8::1`.

The fix keeps the regex crate and its SIMD prefilters, and changes what it sees.
The regex lane scans a **shadow** of the text in which each non-ASCII character
is replaced by a representative with the same UTF-8 length (so every offset is
unchanged) and the same Python `\w`/`\d`/`\s` membership, chosen so that Rust
agrees on it. `\x1c`–`\x1f` become `\x0b`. No pattern has a non-ASCII literal or
a negated class, so no other match decision can change. Validators and boundary
checks read the original text through Python-exact predicates. Pure-ASCII input
(the common case) is scanned in place with no copy.

The predicates come from `native/src/unicode_tables.rs`, which
`native/scripts/gen_unicode_tables.py` generates by asking Python's `re` about every
codepoint (CPython 3.14, Unicode 16.0, the same version as the digit table).
`test_char_classes_match_python_re` re-checks every codepoint against the installed
interpreter. On an older Python it skips codepoints that its Unicode database
leaves unassigned, because those characters were assigned later. Across Python
3.10–3.14, every disagreement with the tables is of that kind; no
assigned codepoint changes class.

### The crate as a Rust library

`native/` builds two ways. By default it is a plain Rust library (`rlib`, no
PyO3 and no libpython), with `detect(text) -> Vec<Detection>` in byte offsets,
`detect_char_offsets` in Python's character offsets, and `patterns()`. With
`--features python`, which maturin enables through `[tool.maturin]`, it is the
`safestream_native` extension, a thin binding in `src/python.rs`. `cargo test` runs
the Rust unit tests without Python. The byte-identity gate against Python remains
`tests/test_native_backend.py`.

### Sub-step (e) — entropy tiers in Rust: built, **bit-identical**, shipped

`native/src/entropy.rs` implements `EntropyDetector` and `CompoundSecretDetector`.
Candidates come from a byte scanner equivalent to the two ASCII-class regexes
(maximal runs split greedily into `MAX_SPAN` pieces; a remainder under 20 is not a
match). The gates are pure functions of the token.

The hazard that declined sub-step (b) was the entropy itself: a float sum compared
against a threshold. It is reproduced operation for operation rather than within a
tolerance:

- terms in `collections.Counter` order (first occurrence of each character);
- each term `(c / n) * log2(c / n)`: exact int-to-float division, then the
  platform `log2`, which both CPython's `math.log2` and Rust's `f64::log2` call;
- the summation `sum()` really performs. CPython 3.12 switched floats from naive
  addition to Neumaier compensated summation, so the Python side probes it at
  import (`sum([1.0, 1e100, 1.0, -1e100]) == 2.0`) and passes the mode in.

The meta string (`f"{entropy:.2f}"`) is still formatted by Python from the
returned float, so formatting cannot diverge.

| Gate | Result |
| --- | --- |
| `tests/test_native_backend.py`: exact float bits on 3 500 random tokens and on tokens at the 4.0 and 3.0 thresholds; detector equivalence (spans, text, meta) on corpora, fragment and character fuzz, runs over `MAX_SPAN` | identical on Python 3.11 (naive), 3.12 and 3.14 (Neumaier) |
| Ad-hoc: 4 000 000 random tokens, both summation modes | **0 bit differences** |

Measured, standalone `detect()` (best of 3): `EntropyDetector` 52.9 → **965 MB/s
(18×)** on the 20 MB baseline corpus; `CompoundSecretDetector` 4.2 → **38 MB/s
(9×)** on text dense with password-style specials (its prefilter already makes it
near-free on text without them).

### Zero-allocation hot path

Scanning a window now performs no heap allocation, proven by
`native/tests/zero_alloc.rs`. A counting global allocator checks that a scan
into a buffer with spare capacity allocates nothing, after a warm-up whose own
allocations show the counter works. The test covers all regex-lane patterns, the
scanners, and both entropy tiers, on ASCII and on non-ASCII text. The changes:

- `luhn_ok` sums digits right to left in one pass; `phone_ok` checks the date and
  SSN shapes against an 11-character stack buffer.
- The structured-phone memo is a fixed stack array sized to the longest possible
  match (36 characters × 4 bytes), invalidated per start with a generation stamp.
- Byte-to-character offsets use a cursor that counts UTF-8 lead bytes between
  consecutive offsets, instead of a sorted vector and a hash map.
- The regex lane copies the text only if it contains a character whose Rust and
  Python classes actually disagree. That set is computed once from `regex-syntax`
  (the parser `regex` uses) and the Python tables, and a unit test checks it
  codepoint by codepoint against the compiled `regex`. Accented Latin, CJK,
  Cyrillic and Arabic-Indic digits are scanned in place.
- `detect_into(text, &mut buf)` lets a Rust caller reuse one output buffer.

### Where end-to-end time goes now

Profile of `Redactor(backend="native").redact` on 20 MB of the baseline corpus
(cProfile, so absolute times are inflated; the shares are the point):

| Stage | Share |
| --- | --- |
| `LabeledIdentifierDetector` (Python) | 63 % |
| the five keyword-triggered credential patterns (Python) | 18 % |
| `ContextualScorer` (Python) | 10 % |
| native deterministic core | 5 % |
| native entropy tiers | < 1 % |

The remaining Python tiers set the CLI throughput: on the 200 MB corpus,
`--backend native` runs at 2.42 MB/s with 1 worker and 9.09 MB/s with 4 (Python:
1.48 and 5.44), byte-identical output in all four runs.

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
  Reverted. Superseded by sub-step (d).
- Sub-step (d) — credit_card/phone as hand-rolled linear scanners: **done** (see
  above). Byte-identical on every gate, including the multi-MB corpus that exposed
  `fancy-regex`. The deterministic tier is 3.9–11.2× faster than pure Python (it
  was 1.7–2.0×).
- Python character classes: **fixed** (see above). The native regex lane's `\w`,
  `\b` and `\s` now follow Python's `re`, and are proven per codepoint.
- Rust library: **done**. `native/` is an `rlib` by default, and the Python
  extension is the `python` feature.
- Sub-step (b) — entropy-tier port **evaluated: declined** at the time, over the
  floating-point byte-identity hazard. Superseded by sub-step (e).
- Sub-step (e) — entropy tiers in Rust: **done**, bit-identical (see above).
- Zero-allocation hot path: **done**, proven by `native/tests/zero_alloc.rs`.
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
- Remaining Python lanes: the five label-gated credential patterns (anthropic/openai
  keys, URL credentials, AWS secret, api_key), `LabeledIdentifierDetector`, and
  `ContextualScorer`. Together they are about 90 % of end-to-end time with the
  native backend (see "Where end-to-end time goes now").
- Maintainer to-do before the first publish (one-time, external to the repo): create
  the `safestream-redactor-native` project on PyPI (and TestPyPI) and add a GitHub
  Trusted Publisher for workflow `native-wheels.yml` with environment `pypi-native`
  (`testpypi-native` on TestPyPI) — as documented in the workflow header.
