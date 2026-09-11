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

## Status

- Step 2 (this doc + `detectors/_lookaround_free.py` + `tests/test_lookaround_free.py`):
  **done** — 19/21 patterns DFA-ready with a proven byte-identical rewrite; the 2
  scanner cases are specified. No production behavior changed (the module is a
  validated spec, not wired into the default pipeline).
- Step 3 (Rust core): not started; awaits review of this plan and the Rust
  toolchain decision (it introduces the `[native]` extra and a wheel build matrix).
