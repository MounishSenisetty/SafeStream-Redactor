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

Two acceptable native implementations, both gated by the same differential test:

- **Preferred: `fancy-regex` (Rust) for these two only.** `fancy-regex` supports
  lookaround/backtracking, so the existing patterns port *verbatim* and stay
  byte-identical by construction. They are digit-gated and only 2 of 21 patterns,
  so running them in a small backtracking "slow lane" alongside the `RegexSet`
  "fast lane" is cheap and simple. Recommended.
- **Alternative: hand-rolled state machine.** Scan for a start (digit not preceded
  by `[\d-]`), greedily consume the core counting digits, then apply the trailing
  boundary with explicit trim-back of trailing groups until the lookahead holds or
  the minimum length is violated; then Luhn / `phone_ok`. More code, more risk;
  only worth it if `fancy-regex` proves too slow (unlikely for a digit-gated,
  2-pattern lane). Must pass the differential+fuzz gate before shipping.

## Native core plan (step 3, gated)

1. `[native]` optional extra + `backend="native"` on the deterministic tier;
   pure-Python stays the default and the byte-identical oracle/fallback.
2. Rust crate (PyO3 + maturin): `aho-corasick` multi-literal prefilter (SIMD
   `memchr`) → `regex` `RegexSet` for the 19 DFA-ready patterns → `fancy-regex`
   slow lane for credit_card/phone → return spans to the existing Python
   arbitration + policy (move those into Rust later only if profiling says so).
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

### The Unicode-`int()` blocker for IPv4/IPv6 (why they are deferred)

Python detects **Unicode-digit** IPv4/IPv6 too (`٩٩.٩.٩.٩` → ipv4), because
`ipv4_ok` calls `int(octet)` and Python's `int()` accepts any Unicode decimal
digit, while Rust's `str::parse`/`char::to_digit` are ASCII-only. A naive Rust
port would therefore **under-detect** Unicode-digit IPv4/IPv6 — a divergence the
gate would (correctly) reject. So IPv4/IPv6 wait for a Unicode-`int()`-equivalent
in Rust (a small Nd→value helper) or an explicit ASCII-fast-path + Python fallback
for the rare Unicode-digit case. `credit_card`/`phone` remain the `fancy-regex`
slow-lane cases. SSN is unaffected because its validator does no integer parsing.

## Status

- Step 2 (`detectors/_lookaround_free.py` + `tests/test_lookaround_free.py`):
  **done** — 19/21 patterns DFA-ready with a proven byte-identical rewrite.
- Step 3 scaffold + sub-step 1 (`native/`, `benchmarks/native_backend.py`,
  `tests/test_native_backend.py`): **done** — toolchain validated; 12 credential
  patterns + SSN are byte-identical and 9–49× faster; findings above. Not wired
  into the default pipeline (zero risk to shipping behavior); the extension is
  optional and built-from-source only.
- **Next sub-steps** (each benchmark- and byte-identity-gated): (a) IPv4/IPv6 once
  the Unicode-`int()` parity is solved (above); (b) add `credit_card`/`phone` via
  the `fancy-regex` slow lane; (c) wire `backend="native"` into the deterministic
  tier behind a `[native]` extra with the pure-Python fallback; (d) run the full
  baseline harness end-to-end and report the real redaction-throughput gain (ship
  only if faster AND identical).
- Open decision for the maintainer before wiring/publishing: whether to publish a
  `safestream-redactor-native` wheel (adds a CI wheel-build matrix) or keep it
  build-from-source; and confirmation to add the optional `[native]` extra.
