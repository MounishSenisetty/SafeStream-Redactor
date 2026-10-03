# Presidio parity: what exists, what was added, what was declined

A requirement-by-requirement audit against Microsoft Presidio's feature set, with the
evidence for each status. "Declined" means measured or reasoned and rejected, not
overlooked. Numbers come from [`benchmarks/PRESIDIO_COMPARISON.md`](../benchmarks/PRESIDIO_COMPARISON.md)
(one run, 4 vCPU shared container).

## Recognizers

| Capability | Status | Where |
| --- | --- | --- |
| Pattern / regex recognizers | **Have** | `detectors/deterministic.py` (~23 patterns), Rust core in `native/` |
| Checksum-validated: credit card (Luhn), SSN structure | **Have** | `deterministic.luhn_ok`, SSN area/group rules |
| Checksum-validated: IBAN, UK NHS, India Aadhaar, Bitcoin (base58check, bech32/m) | **Added (opt-in)** | `detectors/regional.py` |
| Shape-validated only: UK NINO, India PAN, Ethereum address | **Added (opt-in)** | no checksum exists / needs Keccak-256 (not in the stdlib) |
| MAC address (Presidio reports it as `IP_ADDRESS`) | **Added** | `mac_address`, default on |
| AWS account ID (ARN / endpoint / ECR framed) | **Added** | `aws_account_id`, default on. Presidio has no equivalent |
| `DATE_TIME` | **Added (opt-in)** | `date`: `--dates` / `use_dates=True`. Off by default because log timestamps would be redacted |
| Shannon-entropy secrets and tokens | **Have** | `detectors/entropy.py` (+ compound-secret tier) |
| Context-aware scoring (boost/suppress by nearby words) | **Have** | `detectors/contextual.py` (48-character left window), `labeled_id.py` cue cascade |
| Custom recognizers by config or plugin | **Have** | `--custom-regex`, TOML `[custom]`, entry-point plugins |
| EU national IDs (DE, ES, IT, FR, ...) | **Gap** | only IBAN is covered; add per-country tiers when a use case names them |

The regional tier is **off by default** (`Redactor(use_regional=True)`, `--regional`, or
naming a regional type in `types`): enabling it changes what existing deployments
redact. A bare 10- or 12-digit run is accepted as an NHS/Aadhaar number only with a cue
word (`NHS`, `Aadhaar`) or the conventional spaced form, because a plain digit run is
an order id or a timestamp as often as an identifier.

## Anonymizer operators

| Operator | Status | Notes |
| --- | --- | --- |
| Replace, Mask | **Have** | `RedactionMode.REPLACE`, `MASK` |
| Pseudonymize (keyed) | **Have** | HMAC-SHA-256; equality-preserving |
| Hash | **Added** | `--mode hash`; salted SHA-256/512. Unkeyed hashing of a low-cardinality value is brute-forceable, so set a secret `--hash-salt` or prefer pseudonymize |
| Encrypt + Deanonymize | **Added** | `--mode encrypt`, `safestream deanonymize`; AES-256-GCM, needs the `crypto` extra |
| Fictionalize / synthesize | **Added** | `--mode fictionalize`; reserved ranges (`example.com`, TEST-NET, `555-01xx`, 9xx SSN areas) |

Every operator is a pure function of `(key, entity type, matched text)`. That is
load-bearing: streaming and parallel output are proven byte-identical to a
whole-document pass only because rewriting a span depends on nothing but the span. A
random nonce would break the theorem, so **Encrypt uses a synthetic, SIV-style nonce**
(HMAC of type and plaintext): equal values give equal tokens (the same equality leak
`pseudonymize` has), the entity type is authenticated so a token cannot be relabelled,
and a token that fails authentication is left in place and counted, never replaced with
garbage. `tests/test_operators.py` checks streaming == whole for every operator.

## Streaming and performance

| Requirement | Status | Evidence |
| --- | --- | --- |
| O(1)-memory chunking with exact boundary handling | **Have** | `engine.py`; `docs/FORMAL_MODEL.md` Theorems 1-3; `tests/test_equivalence_fuzz.py` |
| Multiprocessing across cores | **Have** | `parallel.py`; byte-identical to sequential, seam-checked |
| `mmap` / zero-copy ingestion | **Declined** | measured: detection, not input I/O, is the bottleneck; `docs/ZERO_COPY.md`. Workers already read their own byte ranges and never ship payloads over IPC |
| `regex` / Hyperscan / re2 backend | **Declined** | re2 cannot compile 10 of 23 patterns and changes output on Unicode; `docs/PERFORMANCE_BACKENDS.md`. The Rust core is the accelerator that kept output byte-identical |
| Fast-path triage (prefilter, then regex/checksum, then entropy, then NER) | **Mostly have** | anchor prefilter is ~25x on secret-sparse text. **Gap:** NER runs on all text when enabled (0.04 MB/s); gating it on cheap ambiguity signals is the largest untried NER-tier lever |

## Interfaces and operations

| Requirement | Status | Notes |
| --- | --- | --- |
| MCP server (stdio) | **Have** | `mcp_server.py`: `scan`, `analyze_text`, `redact`, `redact_text`, `explain_detection`, `detectors`, `health`, sandboxed file tools. Metadata only, never the matched secret |
| MCP SSE transport; a read-only `inspect_stream` file-audit tool | **Not in this change** | |
| Async REST (FastAPI) | **Declined (owner decision)** | the REST API is stdlib `http.server` by design so the core install has zero runtime dependencies; FastAPI adds Starlette, Pydantic and an ASGI server to it. If wanted, ship it as an optional extra rather than replacing the stdlib server |
| Structured logging, metrics | **Partial** | `--report` JSON (counts and sizes, never text), `--stats`; stdlib `logging` is used, `loguru` is not added (a dependency for no capability) |
| Multi-stage Docker | **Have** | `Dockerfile`: hash-locked build, digest-pinned base, non-root. **Added** `docker-compose.yml` (no network, read-only root, 64 MiB cap). NER models are not baked in: the image is core-only by design |
| `mypy --strict`, tests, fuzzing, benchmark vs Presidio | **Have** | CI; `tests/test_equivalence_fuzz.py`; `benchmarks/presidio_compare.py` |

## Declined: renaming the package to `safestream/`

The requested layout (`core/`, `engine/`, `recognizers/`, ...) would rename the
published `safestream_redactor` package: every user import, the `safestream` entry
point, the native-wheel spec guard, the plugin entry-point group, the docs and the
paper's artefact references would all break, for a layout that is already modular
(`detectors/`, `ui/`, `memstream/`, `parallel.py`, `memory_budget.py`). The project's
rule is deprecate-first for public API. The honest cost-benefit is negative, so it was
not done.

## Does it "surpass Presidio"?

Measured, like for like (see the comparison page for tiers and caveats):

| | Result |
| --- | --- |
| Pattern tier speed vs Presidio's own pattern recognizers | 15-147x faster, using 2.7-14x less memory |
| Pattern tier precision / character recall on real prose | 0.754 / 0.412 vs 0.422 / 0.292 |
| NER tier speed (same `en_core_web_sm`) | about 2x faster, but about 2.5x **more** memory |
| NER tier entity recall on real prose | 0.520 vs Presidio's 0.659: **Presidio is better** |

So: faster, leaner and more precise on rule-based detection, with a stated memory
bound and an equivalence proof Presidio does not offer; not better on NER recall. That is
what the code supports, and the claims in the README are limited to it.
