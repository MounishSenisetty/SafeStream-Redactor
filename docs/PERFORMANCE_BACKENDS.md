# Tier-1 regex backend: re2 / Vectorscan evaluation and decision

**Decision: not adopted.** A compiled-regex backend (google-re2, and by
extension Vectorscan/Hyperscan) for the deterministic tier both **changes the
output** — a redaction-safety regression — **and** gives no end-to-end
throughput gain on realistic workloads. Per the project rule *"don't merge a
backend that changes output,"* the pure-Python `re` engine remains the shipping
path. This document records the measured evidence so the decision is auditable
and can be revisited if the patterns are ever rewritten to be
lookaround-free and Unicode-boundary-consistent (a larger project).

Reproduce with `pip install google-re2 && python benchmarks/re2_backend.py`.

## The idea

The deterministic tier runs ~23 compiled patterns per window; on paper a
single-pass DFA scanner (re2) or a multi-pattern engine (Hyperscan/Vectorscan)
could replace the N sequential Python passes. We prototyped a **hybrid** backend
(`benchmarks/re2_backend.py`): re2 for the patterns it can compile, Python `re`
for the rest, keeping the anchor prefilter unchanged.

## Blocker 1 — re2 cannot compile the throughput-dominating patterns

RE2 rejects lookahead/lookbehind and large bounded repetitions. Of 23 tier-1
patterns, **10 do not compile**, and they are exactly the ones that run on
ordinary text:

| Cannot compile on re2 | Why |
| --- | --- |
| `ssn`, `credit_card`, `ipv4`, `ipv6`, `phone` (×2) | `(?<!…)` / `(?!…)` boundary guards |
| `aws_secret`, `anthropic_key`, `openai_key` | lookahead / lookbehind |
| `private_key` | `{1,8100}?` exceeds re2's repetition limit |

The 13 that *do* compile are the credential patterns anchored by distinctive
literals (`AKIA`, `ghp_`, `eyJ`, …) — the ones the **anchor prefilter already
skips** on non-matching text. So re2 can only accelerate work the prefilter has
already eliminated, while the patterns that actually cost time (SSN, card, IPv4,
phone, IPv6 — they run on any digit-bearing line) stay in Python.

## Blocker 2 — re2 changes output on Unicode (under-detects)

Even for the 13 "compatible" patterns, re2's `\b`, `\w`, and `\d` are
**ASCII-only**, whereas Python's are **Unicode-aware**. On the ASCII test corpus
they look identical, but on Unicode-adjacent text they diverge — and re2's
divergence is the dangerous direction, emitting matches Python correctly rejects:

| Input | Python `re` | google-re2 |
| --- | --- | --- |
| `文字bob@corp.io文字` | *(no match — `文` is a word char, no boundary)* | matches `bob@corp.io` |
| `naïvebob@corp.io` | *(no match)* | matches `vebob@corp.io` |
| `٠٩bob@x.io` (Arabic-Indic digits) | *(no match)* | matches `bob@x.io` |
| `…POk6yنص` (JWT + Arabic) | *(no match)* | matches the JWT |

5/5 Unicode probes diverged. For a redaction tool, a backend that silently
matches *different* spans than the reference engine is unacceptable regardless of
speed: it would change what gets redacted. `google-re2` exposes no option to make
`\b` Unicode-aware, so this is not tunable away.

## Blocker 3 — no end-to-end speedup anyway

Measured with `benchmarks/re2_backend.py` (best of 3, dev container), end-to-end
`DeterministicDetector.detect` with the prefilter on:

<!-- MEASURED:BEGIN -->
| Corpus | Python `re` | hybrid-re2 | ratio |
| --- | --- | --- | --- |
| realistic log (PII-heavy: email/ip/card/ssn) | ~2.82 MB/s | ~2.82 MB/s | 1.00× |
| credential + PII mix | ~2.95 MB/s | ~2.63 MB/s | 0.89× |
<!-- MEASURED:END -->

re2 is neutral on the realistic log and ~11% **slower** on credential-dense text
(its per-match C-boundary overhead exceeds the DFA win once matches are
frequent). A micro-benchmark of the compatible subset *without* the prefilter
shows re2 at 6.3× on sparse prose — but that win evaporates end-to-end because
the prefilter already skips those patterns on prose, and re2 is 0.78× on dense
credential text.

## Why Hyperscan/Vectorscan would hit the same wall

Hyperscan is faster still for multi-pattern matching, but it shares re2's two
fatal constraints here: no lookaround (so the same 10 PII/secret patterns can't
move) and ASCII-only `\b`/`\w` semantics (same Unicode divergence). It also
reports end-offsets and all (overlapping) matches, making byte-identical span
reconstruction harder, and it needs a heavy native dependency. Same wall, more
cost.

## When to revisit

A compiled backend only becomes worthwhile if the **lookaround PII patterns**
(SSN, card, IPv4, phone, IPv6) are first rewritten as lookaround-free candidate
regexes with the boundary logic moved into their validators (the tier already
uses candidate+validator for several of these), *and* the Unicode-boundary
semantics are reconciled (explicit Unicode-consistent boundary classes instead
of `\b`). That is a substantial, separately-tested change to the core detection
semantics — tracked in the roadmap, not attempted here, because the current
evidence shows no payoff without it. The throughput headline stands as the README
states it: ~3 MB/s single-core, improved primarily by the intra-file parallelism
(`--workers N`), not by swapping the regex engine.
