# Gap report: SafeStream-Redactor vs Microsoft Presidio (Phase 0)

Status: **in progress.** This report drives the Phase 1–3 backlog. Everything here
comes from **dev** splits only; no test split has been scored. The per-corpus
Presidio comparison tables are added after the clean baseline run (AC power,
isolated virtualenvs, one thread per tool), so every number below either does not
depend on power or memory, or is labelled as preliminary.

## 1. Evaluation hygiene

| Corpus | Role | Dev / test docs | Note |
| --- | --- | --- | --- |
| presidio-research (`synth_dataset_v2.json`, MIT) | **headline test set** | 750 / 750 | never used for tuning |
| ai4privacy pii-masking-300k, English validation | **headline test set** | 3,973 / 3,973 | academic non-commercial licence; data never committed; acknowledgement: AI4Privacy |
| secrets (Nosey Parker rule examples, Apache-2.0, + generated negatives) | **headline test set** | 313 / 313 | split by rule, so test holds vendor formats dev never saw |
| RedactionBench | reported with caveat | 100 / 100 | **previously exposed**: all 200 documents were used for tuning before the split |
| CoNLL-2003 test | reported, not counted as independent for the ONNX tier | 173 / 173 | the bundled ONNX model was trained on CoNLL train |
| n2c2 / i2b2 2014 | loader only | — | data use agreement |

Splits are fixed (seed 20261003) and committed as id manifests with the source
SHA-256 (`benchmarks/corpora/splits/`). The loader refuses a split whose source
changed. The secrets corpus definition changed once, before any test score existed
(commit `71be3e8`): Nosey Parker's `negative_examples` were dropped, because they
mean "this rule must not fire" and contain real emails, IPs and secret-shaped
values.

## 2. Correctness defects found in Phase 0

| Defect | Effect | Status |
| --- | --- | --- |
| ONNX INT8 batching made output depend on chunking | 225 of 2,585 spans changed between 16K and 24K chunks on one document; parallel output not guaranteed equal to sequential | **fixed** (`b8d00f8`): one window per call by default, batching opt-in; batch size 1 was also 1.2–1.5× faster |
| README ONNX throughput (0.04 MB/s) | measured on a corpus that is 80% logs; prose runs at ~0.003–0.008 MB/s | README fix pending (Phase 0 step 0.2) |
| Earlier "parallel ≡ sequential with ONNX" check was vacuous | files under 8 MB are never split | replaced by tests that force splits for every config (`7b719a4`, `b8d00f8`) |
| `--regional` misses an Ethereum address and flags a Luhn-valid digit run inside it as a credit card | `0x5290…9EE7` → `credit_card` on `52908400098527886`; the rest of the address stays in clear | Phase 1 |
| Presidio's memory/load in a shared environment | importing Presidio loaded torch (34 s, 538 MB) because it was installed for another config | harness now runs each tool family in its own virtualenv; Presidio-regex: 4.4 s load, 82 MB |

## 3. Secrets (dev, `safestream-native`, current split)

210 documents hold 260 gold secrets; 103 documents are generated non-secrets.
95% bootstrap CIs over documents.

| Metric | Value |
| --- | --- |
| Secrets fully redacted (covered entity recall) | **0.542** [0.481, 0.606] |
| Character recall | 0.814 [0.761, 0.860] |
| Character precision | 0.524 [0.438, 0.609] |
| False-positive document rate (generated non-secrets) | **0.806** [0.729, 0.880] |
| Presidio-regex, fully redacted | 0.131 [0.093, 0.171] (no credential recognizers; hits are incidental URL/IP/email matches) |

**Leaks: 119 of 260 secrets** (88 not redacted at all, 31 partially). By cause:

| Cause | Examples (Nosey Parker rule) | Leaks |
| --- | --- | --- |
| Vendor keys with no detector | Auth0, Heroku and Jenkins tokens (UUID-shaped), LinkedIn key/secret pairs, Mailgun `key-…`, Postmark, Shopify, New Relic `NRAA-…`, Salesforce, Tavily, StackHawk, PHPMailer `$mail->Password`, React-app env keys, AWS secret after `=>` | 32 |
| Connection strings with a password | `postgresql://user:secret@localhost`, ADO `…;Password=…`, Azure App Config `Endpoint=…;Id=…;Secret=…` (postgres.1, generic.10, azure.2) | 28 |
| Password assignments: the value after a `password`/`pass` key | `password = 'open sesame'`, `password => "super$ecret"`, `"AdminPassword" : "…"`, `<add key="FromEmailPassword" value="…"/>`, `The default Password is '…'` (generic.3/5/9/11) | 22 |
| Partial vendor tokens: prefix or tail left in clear | Doppler `dp.st.dev.` prefix, Dropbox last 3 chars, Dynatrace `dt0c01.` prefix, Azure key final `=`, HashiCorp, Mapbox, MS Teams webhook, Telegram | 20 |
| ARNs / bucket URLs (low sensitivity; Nosey Parker labels them) | `arn:aws:s3:::bucket`, `storage.googleapis.com/bucket` | 10 |
| Password hashes cut at `.`, `/` or `$` | `$8$…$…` Cisco type 8, `$krb5asrep$23$…` (pwhash.5, krb5) | 7 |

**False alarms.** The entropy tier flags **every** generated UUID
(`request_id=2ba5…`), commit SHA-1, SHA-256 digest and base64 PNG data URI as a
`secret` (83 of 83); minified JS 0 of 20. Inside positive documents, 104
predicted spans touch no gold character; many are adjacent real credentials that
Nosey Parker's single capture group does not label (client ids next to secrets),
so character precision understates true precision there. That is Nosey Parker's
labelling; it is not relabelled.

## 4. Preliminary: presidio-research dev (accuracy only)

Measured before the ONNX batching fix and outside the isolated venvs, so
throughput/memory are void and the ONNX row will change.

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) |
| --- | --- | --- | --- | --- | --- |
| safestream-native | pattern | 0.992 | 0.162 | 0.278 [0.243, 0.314] | 0.112 |
| presidio-regex | pattern | 0.915 | 0.181 | 0.303 [0.267, 0.338] | 0.127 |
| safestream-native + gated ONNX (batched) | NER | 0.953 | 0.579 | **0.720** [0.695, 0.744] | 0.503 [0.468, 0.537] |
| presidio-lg | NER | 0.834 | 0.527 | 0.646 [0.622, 0.669] | **0.545** [0.515, 0.576] |

Pattern tier: Presidio-regex finds URLs (19 gold) and IBANs (7) that SafeStream's
default tier does not (IBAN is in the opt-in regional tier; URL has no detector),
and more dates (opt-in in SafeStream). NER tier: SafeStream leads on character
F1 with non-overlapping CIs; Presidio-lg leads on covered entity recall (CIs
overlap). Neither detects AGE, TITLE or NRP.

## 5. Phase 1 backlog, in order

1. Password/secret assignments: tokenize `key=value`/`key: value`/`key => value`/XML
   `value=` on separators and score the value after a secret-like key, letters-only
   values included.
2. Connection strings: ADO/ODBC `Password=`/`Pwd=`, Azure `Secret=`, every URI scheme
   with `user:pass@`.
3. Entropy-tier false alarms: UUIDs, commit/digest hashes in hash contexts, `data:`
   image URIs. This is a precision change, so it lands with before/after numbers.
4. Full-span vendor tokens (Doppler, Dropbox, Dynatrace, Azure trailing `=`) and new
   vendor families (Auth0, Heroku, Mailgun, Postmark, Shopify, New Relic, LinkedIn…),
   each with a vendor-prefix anchor.
5. Password hashes: bcrypt/argon2/scrypt/PBKDF2/crypt(3)/Cisco/Kerberos, whole span.
6. URL and IBAN in the default tier; Ethereum address fix; then the remaining
   Presidio entity-parity items and non-US addresses, ordered by the baseline tables.
