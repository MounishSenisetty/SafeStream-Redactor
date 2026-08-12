# ADR 0002 — Why not a compiled-regex backend (yet)

- Status: accepted
- Date: 2026-08-12

## Problem

Single-core detection runs at ~3–5 MB/s. Compiled multi-pattern engines
(Intel Hyperscan / Vectorscan, Google RE2) scan at hundreds of MB/s to GB/s and
are the obvious candidate for a large throughput win. The question is whether
one is *justified* for this specific pattern set, measured rather than assumed.

## What was measured

All numbers below are on this machine (4 cores), reproducible with the corpora
in `benchmarks/`. "Realistic sparse" is a 20 MB synthetic log stream with PII on
~1 in 50 lines and timestamps/status codes on every line (built in the eval
scripts); it is the case that matters for real-world throughput, because real
logs are secret-*sparse* but digit-*dense*.

**Where the time goes (stdlib, per pattern, realistic sparse 20 MB):**
the digit-gated numeric patterns dominate — `credit_card` ~800 ms, `ipv4`
~550 ms, `ipv6` ~560 ms (engaged by every `HH:MM:SS` timestamp), `ssn` ~480 ms,
`phone` ~840 ms combined. These run on essentially all text because logs contain
digits everywhere, so the anchored prefilter (great on digit-free prose) cannot
skip them.

**RE2, per pattern, same corpus:** total stdlib 6.6 s → RE2 1.8 s (~3.7×), with
identical match counts on compatible patterns; up to 25× on the `api_key`
alternation. But three of the patterns that actually cost the most on real data
are **RE2-incompatible**: `private_key` (bounded lazy `{1,8192}?`), `ipv6` and
the bare `phone` pattern (lookbehind `(?<!…)`), which RE2 rejects outright.

**Hyperscan:** compilation of the pattern set with `SOM_LEFTMOST` (needed for
match start offsets) did not complete — it hangs on several patterns. Its
Python match callback also costs one Python call per match, which collapses its
advantage on match-dense text. Rejected as unworkable for this pattern set.

**The correctness gate.** RE2's `finditer` is non-overlapping and greedy, so it
does **not** reproduce the stdlib pipeline's matches for patterns with
overlapping candidates (`credit_card`): a 40 000-input differential fuzz showed
105 mismatches. A "safe-region" arbitration — use RE2 to find candidates, expand
each to a boundary character that no match can contain, then run the stdlib
regex over the region as the final arbiter — **is** provably equivalent: the
same fuzz over 60 000 inputs / 62 647 detections produced **zero** mismatches.

**But the safe-region path is slower, not faster** on realistic data: 2.0 MB/s
vs 5.0 MB/s stdlib. The match alphabet (digits, letters, space, `.-:@/_+=`) is
so broad that "safe regions" cover almost the whole text, so the stdlib arbiter
still scans everything — plus the RE2 scan and region bookkeeping on top.

## Decision

**Do not add a compiled-regex backend now.** The evidence says it does not help
this pattern set's real bottleneck:

- The patterns RE2 accelerates cleanly (credentials, email) are already
  prefiltered to near-zero cost on realistic data, because their literal anchors
  are absent.
- The patterns that actually dominate realistic-data cost (`credit_card`
  greedy, `ipv6`, lookbehind `phone`) are precisely the ones RE2 can't safely
  replace or Hyperscan can't compile.
- The only *correct* way to use RE2 here (safe-region arbitration) is measurably
  slower on realistic data, and using RE2's matcher directly is not
  output-equivalent.

Adding a C dependency (supply-chain surface, build complexity, a second engine
to keep in sync) for a negative or negative-leaning result is exactly the kind
of "technology for its own sake" the project avoids.

## What we did instead

Optimize the actual hot patterns in the stdlib engine, each proven
output-identical by a differential test:

- `ipv4`: inline octet alternation → cheap shape regex + `ipv4_ok` validator (~2×).
- `credit_card`: separator-heavy `(?:\d[ -]?){12,18}\d` → `\d(?:[ -]?\d){12,18}`
  (~1.5×).

And rely on the already-shipped intra-file parallelism (ADR 0001, ~3.7× on
4 cores) as the real throughput multiplier.

## Consequences

- A true 100 MB/s *single-core* is not achievable in pure Python for validated,
  multi-pattern detection; this is stated honestly in the README rather than
  claimed. Aggregate throughput scales with cores via ADR 0001.
- If the pattern set later shifts toward literal-heavy secrets (where RE2 excels
  and prefiltering already helps), or if the numeric patterns are rewritten into
  overlap-free forms, this decision should be revisited — the safe-region
  correctness proof and the measurements here are the starting point.
