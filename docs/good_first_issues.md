# Starter "good first issue" descriptions

Copy each of these into a new GitHub issue with the `good first issue` label.

---

## 1. Add an IBAN detector

**Labels:** `good first issue`, `enhancement`, `detector`

International Bank Account Numbers are common PII in financial logs. Add an `IBAN` entity
type and a pattern in `src/safestream_redactor/detectors/deterministic.py`. IBANs have a
country-specific length and a mod-97 checksum (ISO 13616) — implement the checksum as the
validator, mirroring how credit cards use `luhn_ok`. Add positive tests (a few real-format
IBANs from different countries) and negative tests (bad checksum) in `tests/test_detectors.py`.

## 2. Add a MAC address detector

**Labels:** `good first issue`, `enhancement`, `detector`

Add a `MAC_ADDRESS` entity type matching `aa:bb:cc:dd:ee:ff` and `AA-BB-CC-DD-EE-FF` forms.
Careful: the pattern must not fire inside IPv6 addresses — add a test proving an IPv6 address
is still detected as IPv6, not as a MAC.

## 3. Support `--output-dir` batch mode in the CLI

**Labels:** `good first issue`, `enhancement`, `cli`

`safestream redact` currently takes one input file. Accept multiple inputs plus an
`--output-dir` flag that writes each redacted file to that directory under its original
name. Error clearly if `--output-dir` is combined with `-o`.

## 4. Add a `--summary` flag that prints redaction counts

**Labels:** `good first issue`, `enhancement`, `cli`

After `safestream redact`, print (to stderr, so it doesn't pollute `-o -` output) a per-type
count of what was redacted, e.g. `email: 12, ssn: 3`. The engine already yields detections;
you mostly need to thread a counter through `_cmd_redact`.

## 5. Detect US EIN (Employer Identification Numbers)

**Labels:** `good first issue`, `enhancement`, `detector`

EINs look like `12-3456789`. Bare, they collide with phone-ish digit runs, so follow the
pattern used for bare 9-digit SSNs in `detectors/contextual.py`: only report an EIN when a
trigger word ("ein", "employer id", "tax id") appears nearby.

## 6. Add JSON Lines output to `safestream detect`

**Labels:** `good first issue`, `enhancement`, `cli`

`safestream detect --json` already emits one JSON object per line, but there's no way to
write it to a file. Add `-o/--output` support to the `detect` subcommand, mirroring `redact`.

## 7. Improve phone number precision with date suppression

**Labels:** `good first issue`, `detection-quality`

Strings like `2024-01-01` can be scored as phone numbers in some contexts. Add a validator
or contextual suppression rule that lowers confidence when the match looks like an ISO date
(YYYY-MM-DD with plausible month/day ranges). Include regression tests with both a real
phone number and a list of dates.

## 8. Add a `redact_bytes` API for binary-safe streaming

**Labels:** `good first issue`, `enhancement`, `api`

`Redactor.redact_stream` works on `str` chunks. Add a thin wrapper that accepts `bytes`
chunks plus an encoding, decodes incrementally (`codecs.getincrementaldecoder` handles
multi-byte characters split across chunks), and yields encoded bytes back.

## 9. Publish benchmark results in the README

**Labels:** `good first issue`, `docs`

The README comparison table is a placeholder. Run `benchmarks/generate_dataset.py` and
`benchmarks/run_benchmark.py` (with Presidio installed) on a 50 MB dataset, and fill in the
table with your measured precision/recall/F1 and MB/s, noting your hardware.

## 10. Add `--fail-on-detect` exit code mode for CI secret scanning

**Labels:** `good first issue`, `enhancement`, `cli`

Add a flag to `safestream detect` that exits non-zero when anything is detected, so the CLI
can gate CI pipelines (like a lightweight secret scanner): `safestream detect build.log
--fail-on-detect --types aws_key,github_token,private_key`. Document the pattern in the README.
