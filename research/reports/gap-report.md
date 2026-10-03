# Gap report: SafeStream-Redactor vs Microsoft Presidio (Phase 0)

Status: **Phase 0 complete (dev only).** No test split has been scored. Every number
comes from one harness run (`benchmarks/harness.py`, commit `cebe741`, 2026-10-03):
55 (system, corpus) runs, all from a clean tree, all finishing on AC power, every tool
in its own virtualenv and pinned to one thread. All ran in the Windows *Best power
efficiency* power mode: speeds are throttled in absolute terms but comparable between
tools. Raw JSON/MD: `research/results/raw/2026-10-03_*_dev.*`. Tables below are
generated from that JSON by `benchmarks/summarize.py`, not retyped.

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
| ONNX INT8 batching made output depend on chunking | 225 of 2,585 spans changed between 16K and 24K chunks on one document; parallel output not guaranteed equal to sequential | **fixed** (`b8d00f8`): one window per call by default, batching opt-in; no consistent speed cost (§6) |
| README ONNX throughput (0.04 MB/s) | measured on a corpus that is 80% logs; prose runs at ~0.003–0.008 MB/s | README now quotes measured per-corpus figures (0.007–0.10 MB/s, one thread) |
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

## 4. Summary: every system on every corpus (dev)

Character metrics are type-agnostic: did the sensitive characters get hidden? Entity
metrics are type-agnostic partial match. "Fully redacted" is the share of gold entities
with every character redacted. Tiers: `pattern` means no ML on either side; `ner` means
a model is involved.

SafeStream configurations:

- `native`: the Rust core with the default tiers.
- `-dates`: adds the opt-in date tier.
- `-onnx`: adds the gated INT8 DistilBERT, one window per inference call.
- `-onnx-batched`: the same, with batching opted in.
- `-spacy`: adds spaCy `en_core_web_sm`.

Presidio configurations:

- `regex`: pattern recognizers only, no NLP engine.
- `sm` / `lg`: the full engine on spaCy.
- `trf-deid`: transformers with `StanfordAIMI/stanford-deidentifier-base`.
- `trf-bert`: transformers with `dslim/bert-base-NER`.

#### presidio_research (dev, 750 documents)

| System | Tier | Char P | Char R | Char F1 | Entity P | Entity R | Entity F1 | Fully redacted | FP doc rate | MB/s (1 thread) |
|---|---|---|---|---|---|---|---|---|---|---|
| safestream-python | pattern | 0.992 [0.986, 0.997] | 0.162 [0.139, 0.187] | 0.278 [0.243, 0.314] | 0.905 [0.862, 0.943] | 0.110 [0.093, 0.129] | 0.197 [0.168, 0.226] | 0.112 [0.094, 0.131] | 0.000 [0.000, 0.000] | 1.1 |
| safestream-native | pattern | 0.992 [0.986, 0.997] | 0.162 [0.139, 0.187] | 0.278 [0.243, 0.314] | 0.905 [0.862, 0.943] | 0.110 [0.093, 0.129] | 0.197 [0.168, 0.226] | 0.112 [0.094, 0.131] | 0.000 [0.000, 0.000] | 3.02 |
| safestream-native-dates | pattern | 0.993 [0.987, 0.997] | 0.174 [0.151, 0.201] | 0.297 [0.262, 0.334] | 0.914 [0.874, 0.948] | 0.123 [0.105, 0.143] | 0.217 [0.188, 0.248] | 0.125 [0.106, 0.146] | 0.000 [0.000, 0.000] | 2.04 |
| safestream-native-onnx | ner | 0.950 [0.937, 0.963] | 0.577 [0.546, 0.608] | 0.718 [0.693, 0.742] | 0.809 [0.775, 0.841] | 0.527 [0.493, 0.561] | 0.638 [0.608, 0.667] | 0.500 [0.466, 0.534] | 0.080 [0.018, 0.167] | 0.0131 |
| safestream-native-onnx-batched | ner | 0.953 [0.940, 0.965] | 0.577 [0.546, 0.608] | 0.719 [0.694, 0.743] | 0.811 [0.777, 0.843] | 0.526 [0.493, 0.560] | 0.638 [0.608, 0.667] | 0.500 [0.466, 0.534] | 0.080 [0.018, 0.167] | 0.0136 |
| safestream-native-spacy | ner | 0.913 [0.894, 0.929] | 0.572 [0.543, 0.602] | 0.703 [0.680, 0.726] | 0.780 [0.748, 0.810] | 0.521 [0.491, 0.552] | 0.624 [0.597, 0.650] | 0.500 [0.468, 0.531] | 0.120 [0.037, 0.218] | 0.011 |
| presidio-regex | pattern | 0.915 [0.877, 0.949] | 0.181 [0.157, 0.207] | 0.303 [0.267, 0.338] | 0.492 [0.459, 0.527] | 0.140 [0.121, 0.160] | 0.218 [0.193, 0.243] | 0.127 [0.109, 0.147] | 0.000 [0.000, 0.000] | 0.112 |
| presidio-sm | ner | 0.824 [0.795, 0.853] | 0.516 [0.488, 0.544] | 0.634 [0.611, 0.658] | 0.572 [0.542, 0.604] | 0.538 [0.510, 0.567] | 0.555 [0.531, 0.577] | 0.511 [0.483, 0.540] | 0.080 [0.018, 0.167] | 0.00704 |
| presidio-lg | ner | 0.834 [0.807, 0.862] | 0.527 [0.499, 0.555] | 0.646 [0.622, 0.669] | 0.626 [0.596, 0.657] | 0.566 [0.537, 0.595] | 0.594 [0.570, 0.618] | 0.545 [0.515, 0.576] | 0.000 [0.000, 0.000] | 0.00557 |
| presidio-trf-deid | ner | 0.909 [0.892, 0.926] | 0.579 [0.552, 0.605] | 0.708 [0.686, 0.728] | 0.558 [0.526, 0.591] | 0.555 [0.529, 0.578] | 0.557 [0.534, 0.578] | 0.545 [0.518, 0.570] | 0.080 [0.019, 0.158] | 0.000268 |
| presidio-trf-bert | ner | 0.953 [0.938, 0.967] | 0.524 [0.495, 0.553] | 0.676 [0.651, 0.701] | 0.661 [0.628, 0.695] | 0.509 [0.478, 0.541] | 0.575 [0.549, 0.601] | 0.474 [0.444, 0.505] | 0.140 [0.047, 0.236] | 0.000308 |

#### ai4privacy (dev, 3973 documents)

| System | Tier | Char P | Char R | Char F1 | Entity P | Entity R | Entity F1 | Fully redacted | FP doc rate | MB/s (1 thread) |
|---|---|---|---|---|---|---|---|---|---|---|
| safestream-python | pattern | 0.966 [0.960, 0.972] | 0.308 [0.296, 0.319] | 0.467 [0.453, 0.480] | 0.974 [0.969, 0.979] | 0.179 [0.172, 0.187] | 0.303 [0.292, 0.313] | 0.186 [0.178, 0.194] | 0.009 [0.002, 0.019] | 1.39 |
| safestream-native | pattern | 0.966 [0.960, 0.972] | 0.308 [0.296, 0.319] | 0.467 [0.453, 0.480] | 0.974 [0.969, 0.979] | 0.179 [0.172, 0.187] | 0.303 [0.292, 0.313] | 0.186 [0.178, 0.194] | 0.009 [0.002, 0.019] | 9.54 |
| safestream-native-dates | pattern | 0.956 [0.950, 0.961] | 0.418 [0.407, 0.429] | 0.581 [0.570, 0.592] | 0.954 [0.947, 0.960] | 0.282 [0.273, 0.290] | 0.435 [0.425, 0.445] | 0.291 [0.282, 0.300] | 0.045 [0.027, 0.065] | 3.62 |
| safestream-native-onnx | ner | 0.780 [0.768, 0.792] | 0.456 [0.446, 0.467] | 0.576 [0.566, 0.586] | 0.762 [0.751, 0.773] | 0.319 [0.310, 0.328] | 0.450 [0.440, 0.459] | 0.338 [0.328, 0.348] | 0.466 [0.421, 0.510] | 0.0203 |
| safestream-native-onnx-batched | ner | 0.783 [0.771, 0.795] | 0.457 [0.446, 0.467] | 0.577 [0.567, 0.587] | 0.767 [0.755, 0.778] | 0.319 [0.310, 0.328] | 0.450 [0.440, 0.460] | 0.338 [0.328, 0.348] | 0.451 [0.407, 0.496] | 0.0195 |
| safestream-native-spacy | ner | 0.672 [0.659, 0.686] | 0.418 [0.407, 0.429] | 0.515 [0.505, 0.526] | 0.710 [0.697, 0.722] | 0.295 [0.287, 0.303] | 0.417 [0.408, 0.426] | 0.309 [0.300, 0.318] | 0.496 [0.451, 0.544] | 0.0538 |
| presidio-regex | pattern | 0.747 [0.735, 0.758] | 0.439 [0.428, 0.450] | 0.553 [0.542, 0.563] | 0.359 [0.353, 0.365] | 0.316 [0.306, 0.325] | 0.336 [0.330, 0.342] | 0.286 [0.277, 0.295] | 0.083 [0.058, 0.110] | 0.152 |
| presidio-sm | ner | 0.722 [0.713, 0.732] | 0.596 [0.587, 0.606] | 0.653 [0.646, 0.661] | 0.401 [0.394, 0.408] | 0.469 [0.460, 0.478] | 0.432 [0.427, 0.438] | 0.435 [0.427, 0.444] | 0.368 [0.322, 0.412] | 0.0273 |
| presidio-lg | ner | 0.730 [0.720, 0.739] | 0.612 [0.603, 0.622] | 0.666 [0.658, 0.673] | 0.428 [0.421, 0.436] | 0.494 [0.485, 0.502] | 0.458 [0.453, 0.464] | 0.466 [0.457, 0.475] | 0.334 [0.290, 0.376] | 0.0262 |
| presidio-trf-deid | ner | 0.724 [0.714, 0.733] | 0.743 [0.733, 0.754] | 0.733 [0.726, 0.740] | 0.399 [0.393, 0.405] | 0.596 [0.585, 0.607] | 0.478 [0.473, 0.483] | 0.607 [0.596, 0.618] | 0.200 [0.165, 0.237] | 0.00152 |
| presidio-trf-bert | ner | 0.756 [0.747, 0.766] | 0.596 [0.586, 0.605] | 0.666 [0.659, 0.674] | 0.446 [0.438, 0.454] | 0.488 [0.480, 0.496] | 0.466 [0.460, 0.472] | 0.465 [0.456, 0.473] | 0.184 [0.147, 0.220] | 0.00141 |

#### secrets (dev, 313 documents)

| System | Tier | Char P | Char R | Char F1 | Entity P | Entity R | Entity F1 | Fully redacted | FP doc rate | MB/s (1 thread) |
|---|---|---|---|---|---|---|---|---|---|---|
| safestream-python | pattern | 0.524 [0.438, 0.609] | 0.814 [0.761, 0.860] | 0.637 [0.560, 0.706] | 0.566 [0.515, 0.619] | 0.658 [0.603, 0.718] | 0.609 [0.567, 0.651] | 0.542 [0.481, 0.606] | 0.806 [0.729, 0.880] | 1.12 |
| safestream-native | pattern | 0.524 [0.438, 0.609] | 0.814 [0.761, 0.860] | 0.637 [0.560, 0.706] | 0.566 [0.515, 0.619] | 0.658 [0.603, 0.718] | 0.609 [0.567, 0.651] | 0.542 [0.481, 0.606] | 0.806 [0.729, 0.880] | 3.38 |
| safestream-native-dates | pattern | 0.523 [0.438, 0.609] | 0.814 [0.761, 0.860] | 0.637 [0.560, 0.706] | 0.564 [0.512, 0.617] | 0.658 [0.603, 0.718] | 0.607 [0.565, 0.650] | 0.542 [0.481, 0.606] | 0.806 [0.729, 0.880] | 2.34 |
| safestream-native-onnx | ner | 0.522 [0.437, 0.608] | 0.814 [0.761, 0.860] | 0.636 [0.560, 0.705] | 0.550 [0.497, 0.602] | 0.658 [0.603, 0.718] | 0.599 [0.556, 0.641] | 0.542 [0.481, 0.606] | 0.806 [0.729, 0.880] | 0.105 |
| safestream-native-onnx-batched | ner | 0.522 [0.437, 0.608] | 0.814 [0.761, 0.860] | 0.636 [0.560, 0.705] | 0.550 [0.497, 0.602] | 0.658 [0.603, 0.718] | 0.599 [0.556, 0.641] | 0.542 [0.481, 0.606] | 0.806 [0.729, 0.880] | 0.0888 |
| safestream-native-spacy | ner | 0.500 [0.417, 0.581] | 0.832 [0.779, 0.878] | 0.625 [0.549, 0.692] | 0.451 [0.401, 0.506] | 0.673 [0.619, 0.732] | 0.540 [0.494, 0.587] | 0.565 [0.506, 0.630] | 0.806 [0.729, 0.880] | 0.0362 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.034 [0.022, 0.054] | 0.146 [0.105, 0.189] | 0.055 [0.037, 0.083] | 0.131 [0.091, 0.173] | 0.427 [0.333, 0.522] | 0.0425 |
| presidio-sm | ner | 0.441 [0.305, 0.555] | 0.400 [0.270, 0.513] | 0.420 [0.287, 0.534] | 0.041 [0.028, 0.062] | 0.188 [0.147, 0.237] | 0.067 [0.048, 0.096] | 0.154 [0.111, 0.201] | 0.680 [0.590, 0.767] | 0.0223 |
| presidio-lg | ner | 0.310 [0.239, 0.387] | 0.211 [0.154, 0.285] | 0.251 [0.189, 0.319] | 0.045 [0.030, 0.068] | 0.200 [0.155, 0.248] | 0.073 [0.051, 0.104] | 0.188 [0.143, 0.238] | 0.466 [0.367, 0.560] | 0.02 |
| presidio-trf-deid | ner | 0.438 [0.368, 0.505] | 0.934 [0.905, 0.957] | 0.596 [0.526, 0.658] | 0.127 [0.101, 0.163] | 0.785 [0.733, 0.835] | 0.219 [0.179, 0.272] | 0.735 [0.682, 0.783] | 1.000 [1.000, 1.000] | 0.000249 |
| presidio-trf-bert | ner | 0.292 [0.209, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.034 [0.022, 0.054] | 0.146 [0.105, 0.189] | 0.055 [0.036, 0.083] | 0.131 [0.091, 0.173] | 0.427 [0.333, 0.522] | 0.000185 |

#### redactionbench (dev, 100 documents)

**Previously exposed**: all 200 documents were used to tune rules before the split existed; not a held-out result.

| System | Tier | Char P | Char R | Char F1 | Entity P | Entity R | Entity F1 | Fully redacted | Mandatory R | No-leak docs | MB/s (1 thread) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-python | pattern | 0.730 [0.554, 0.860] | 0.449 [0.390, 0.550] | 0.556 [0.479, 0.622] | 0.674 [0.612, 0.757] | 0.117 [0.092, 0.134] | 0.199 [0.162, 0.224] | 0.533 [0.352, 0.659] | 0.817 [0.653, 0.903] | 0.096 [0.043, 0.158] | 1.23 |
| safestream-native | pattern | 0.730 [0.554, 0.860] | 0.449 [0.390, 0.550] | 0.556 [0.479, 0.622] | 0.674 [0.612, 0.757] | 0.117 [0.092, 0.134] | 0.199 [0.162, 0.224] | 0.533 [0.352, 0.659] | 0.817 [0.653, 0.903] | 0.096 [0.043, 0.158] | 10.9 |
| safestream-native-dates | pattern | 0.609 [0.431, 0.764] | 0.468 [0.409, 0.577] | 0.529 [0.451, 0.590] | 0.455 [0.333, 0.589] | 0.131 [0.113, 0.146] | 0.204 [0.180, 0.224] | 0.603 [0.453, 0.705] | 0.824 [0.667, 0.909] | 0.096 [0.043, 0.158] | 4.13 |
| safestream-native-onnx | ner | 0.694 [0.521, 0.827] | 0.546 [0.494, 0.642] | 0.611 [0.531, 0.662] | 0.504 [0.422, 0.622] | 0.154 [0.141, 0.172] | 0.236 [0.216, 0.264] | 0.608 [0.461, 0.708] | 0.875 [0.761, 0.936] | 0.170 [0.096, 0.250] | 0.0316 |
| safestream-native-onnx-batched | ner | 0.699 [0.524, 0.832] | 0.554 [0.505, 0.643] | 0.618 [0.534, 0.667] | 0.486 [0.395, 0.622] | 0.154 [0.141, 0.172] | 0.234 [0.213, 0.264] | 0.608 [0.462, 0.708] | 0.875 [0.761, 0.936] | 0.170 [0.096, 0.250] | 0.0292 |
| safestream-native-spacy | ner | 0.604 [0.429, 0.754] | 0.592 [0.540, 0.660] | 0.598 [0.487, 0.660] | 0.357 [0.300, 0.448] | 0.158 [0.147, 0.176] | 0.219 [0.200, 0.246] | 0.618 [0.476, 0.714] | 0.877 [0.770, 0.937] | 0.191 [0.113, 0.272] | 0.0691 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.259 [0.208, 0.309] | 0.174 [0.149, 0.201] | 0.208 [0.178, 0.235] | 0.545 [0.397, 0.652] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0646 |
| presidio-sm | ner | 0.376 [0.265, 0.483] | 0.420 [0.382, 0.499] | 0.397 [0.336, 0.435] | 0.245 [0.208, 0.294] | 0.217 [0.191, 0.252] | 0.230 [0.203, 0.263] | 0.641 [0.538, 0.719] | 0.445 [0.384, 0.514] | 0.064 [0.021, 0.112] | 0.0229 |
| presidio-lg | ner | 0.359 [0.268, 0.444] | 0.370 [0.310, 0.483] | 0.364 [0.328, 0.406] | 0.266 [0.224, 0.314] | 0.215 [0.188, 0.249] | 0.237 [0.212, 0.268] | 0.641 [0.538, 0.719] | 0.428 [0.346, 0.507] | 0.064 [0.021, 0.115] | 0.0221 |
| presidio-trf-deid | ner | 0.368 [0.275, 0.458] | 0.614 [0.525, 0.764] | 0.460 [0.394, 0.520] | 0.282 [0.244, 0.330] | 0.284 [0.251, 0.329] | 0.283 [0.256, 0.316] | 0.727 [0.634, 0.789] | 0.908 [0.825, 0.958] | 0.287 [0.198, 0.382] | 0.000369 |
| presidio-trf-bert | ner | 0.381 [0.284, 0.470] | 0.355 [0.293, 0.472] | 0.368 [0.331, 0.422] | 0.291 [0.240, 0.348] | 0.212 [0.186, 0.245] | 0.245 [0.217, 0.278] | 0.606 [0.485, 0.695] | 0.419 [0.335, 0.503] | 0.021 [0.000, 0.053] | 0.000901 |

#### conll2003 (dev, 173 documents)

**Not independent for the ONNX tier**: its model (`dslim/distilbert-NER`) was trained on CoNLL-2003 train.

| System | Tier | Char P | Char R | Char F1 | Entity P | Entity R | Entity F1 | Fully redacted | FP doc rate | MB/s (1 thread) |
|---|---|---|---|---|---|---|---|---|---|---|
| safestream-python | pattern | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.4 |
| safestream-native | pattern | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 16.6 |
| safestream-native-dates | pattern | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 5.07 |
| safestream-native-onnx | ner | 0.898 [0.878, 0.918] | 0.714 [0.677, 0.749] | 0.796 [0.770, 0.818] | 0.819 [0.779, 0.859] | 0.646 [0.606, 0.682] | 0.722 [0.694, 0.748] | 0.648 [0.609, 0.684] | 0.667 [0.000, 1.000] | 0.00744 |
| safestream-native-onnx-batched | ner | 0.897 [0.877, 0.917] | 0.711 [0.674, 0.745] | 0.794 [0.768, 0.815] | 0.816 [0.777, 0.858] | 0.643 [0.603, 0.680] | 0.720 [0.693, 0.745] | 0.645 [0.605, 0.680] | 0.667 [0.000, 1.000] | 0.00983 |
| safestream-native-spacy | ner | 0.855 [0.836, 0.873] | 0.730 [0.698, 0.761] | 0.787 [0.767, 0.808] | 0.940 [0.926, 0.953] | 0.650 [0.619, 0.680] | 0.769 [0.745, 0.791] | 0.692 [0.660, 0.722] | 0.333 [0.000, 1.000] | 0.0551 |
| presidio-regex | pattern | 0.118 [0.086, 0.153] | 0.023 [0.016, 0.030] | 0.038 [0.027, 0.050] | 0.088 [0.062, 0.115] | 0.018 [0.012, 0.024] | 0.030 [0.021, 0.040] | 0.012 [0.007, 0.017] | 0.333 [0.000, 1.000] | 0.102 |
| presidio-sm | ner | 0.585 [0.550, 0.618] | 0.580 [0.545, 0.612] | 0.582 [0.551, 0.612] | 0.520 [0.483, 0.556] | 0.552 [0.521, 0.581] | 0.535 [0.506, 0.565] | 0.572 [0.539, 0.603] | 1.000 [0.000, 1.000] | 0.0236 |
| presidio-lg | ner | 0.634 [0.596, 0.670] | 0.645 [0.613, 0.677] | 0.640 [0.607, 0.670] | 0.604 [0.568, 0.638] | 0.658 [0.629, 0.688] | 0.630 [0.600, 0.657] | 0.651 [0.620, 0.681] | 1.000 [0.000, 1.000] | 0.0224 |
| presidio-trf-deid | ner | 0.577 [0.520, 0.628] | 0.402 [0.358, 0.443] | 0.474 [0.426, 0.519] | 0.475 [0.426, 0.522] | 0.332 [0.296, 0.366] | 0.391 [0.352, 0.428] | 0.337 [0.300, 0.373] | 0.333 [0.000, 1.000] | 0.000524 |
| presidio-trf-bert | ner | 0.764 [0.722, 0.803] | 0.568 [0.523, 0.614] | 0.652 [0.609, 0.691] | 0.717 [0.683, 0.749] | 0.562 [0.519, 0.605] | 0.630 [0.593, 0.666] | 0.558 [0.518, 0.600] | 0.333 [0.000, 1.000] | 0.000578 |


**Memory.** Tool RSS is peak RSS minus what the process held after loading the data.
From the same run:

| Tool | Tool RSS |
| --- | --- |
| SafeStream native | 31–38 MB |
| SafeStream + ONNX | 150–153 MB |
| SafeStream + spaCy | 134–458 MB |
| Presidio regex | 56–79 MB |
| Presidio `sm` | 127–205 MB |
| Presidio `lg` | 703–790 MB |
| Presidio transformers | 766–892 MB |

**ai4privacy's memory column is invalid for every system.** Each tool process also
parsed the whole ai4privacy file, and that transient peak (~220 MB) dominates the
high-water mark. The fix, in Phase 1, is for the harness parent to pass the split's
texts to the child.

## 5. Where Presidio wins, by entity type (dev)

Each row compares the best SafeStream configuration with the best Presidio
configuration for that type, using type-aware partial-match recall / precision. Only
types where one side leads by more than 0.05 recall are listed.

| Corpus | Type | Gold | Best SafeStream R / P | Best Presidio R / P | Winner |
| --- | --- | --: | --- | --- | --- |
| presidio-research | PERSON | 418 | onnx 0.84 / 0.88 | trf-deid 0.90 / 0.62 | Presidio (recall, at lower precision) |
| presidio-research | PHONE_NUMBER | 39 | native 0.59 / 1.00 | trf-deid 0.92 / 0.18 | Presidio (recall) |
| presidio-research | DATE_TIME | 59 | -dates 0.37 / 1.00 | sm 1.00 / 0.15 | Presidio (recall) |
| presidio-research | URL | 19 | 0.00 | regex 1.00 / 0.40 | Presidio (SafeStream has no URL detector) |
| presidio-research | IBAN_CODE | 7 | 0.00 | regex 1.00 / 1.00 | Presidio (IBAN is opt-in in SafeStream) |
| presidio-research | NRP | 27 | 0.00 | sm 0.67 / 0.64 | Presidio (SafeStream has no detector) |
| ai4privacy | ID | 5,003 | native 0.16 / 0.96 | trf-deid 0.90 / 0.20 | Presidio (recall, at 0.20 precision) |
| ai4privacy | PERSON | 2,978 | onnx 0.35 / 0.66 | trf-deid 0.66 / 0.43 | Presidio |
| ai4privacy | LOCATION | 6,180 | onnx 0.34 / 0.69 | trf-bert 0.48 / 0.74 | Presidio |
| ai4privacy | PHONE_NUMBER | 991 | native 0.56 / 0.96 | trf-deid 0.73 / 0.26 | Presidio (recall) |
| CoNLL (not independent) | PERSON / LOCATION | 793 / 836 | onnx 0.84 / 0.70 | trf-bert 0.92 / 0.90 | Presidio |
| presidio-research | CREDIT_CARD | 71 | native 0.93 / 0.97 | regex 0.79 / 1.00 | SafeStream |
| presidio-research | ORGANIZATION | 122 | onnx 0.63 / 0.51 | 0.00 | SafeStream (Presidio's default config drops ORG) |
| ai4privacy | DATE_TIME | 3,906 | -dates 0.72 / 0.92 | lg 0.59 / 0.60 | SafeStream (opt-in tier) |
| secrets | SECRET | 260 | native 0.64 / 0.60 | 0.00 (no secret type) | SafeStream |

Neither tool detects AGE, TITLE, SEX, USERNAME or MISC.

**Dev error examples (SafeStream + ONNX misses).** presidio-research is MIT-licensed,
so it is quoted. ai4privacy's licence forbids redistribution, so its misses are
described, not quoted.

- **Phones.**
  - A plain US number gets no redaction: `to stop receiving messages to 618-226-1460`.
    This should match, so it is investigated first.
  - International and grouped formats are missed: `079 0442 1744`, `0680 298 70 63`,
    `28-64-66-98`, `99 668472`.
  - In ai4privacy, dotted and mixed-separator numbers inside `<Phone>` and `"TEL"`
    fields are missed. `+`-prefixed numbers leave the prefix or the last digit in clear.
- **Names.**
  - Sentence-initial lone first names: `Jennifer is a very sympathetic person.`,
    `Leif, can I please…`.
  - Lowercase names: `cormac had given cormac his address`.
  - Names alone on a signature line.
  - In ai4privacy, names that are values of structured fields: JSON `"LastName"`, XML
    `<GivenName2>`, YAML, and list items under a heading.
- **IDs (ai4privacy).** Driver's licence, passport and ID-card values that have no
  checksum but strong field labels (`Driver's License:`, `ID:`), and alphanumeric
  shapes such as two letters + six digits + two letters.
- **Locations.**
  - Street lines without a US suffix: `Aqqusinersuaq 111`, `Pohlstrasse 9`, `Apt. 026`.
  - ALLCAPS town names.
  - In ai4privacy, the values of `Building`, `State` and `Postcode` fields.
- **Dates.** Years (`founded in 1977`), weekdays (`on Monday morning`) and ISO
  timestamps (`2007-01-17 23:08:55`). SafeStream detects these only with `--dates`.
- **URLs.** Every URL is missed, for example `My website is http://www.OpticalFirm.com.cy/`.
- **IBAN.** `GB27DAKD58401036741857` is either missed or covered for only 14 of its
  22 characters, by another rule. The IBAN validator is in the opt-in regional tier.
- **NRP.** Nationality adjectives: `great Polish food`, `this nice new Czech place`.

## 6. Per-window vs batched ONNX inference (measured)

Same run, one thread. Batching is opt-in (`--onnx-batch-size 32`); per-window is the
deterministic default.

| Corpus | MB/s per-window | MB/s batched | Batched vs per-window | Char F1 per-window | Char F1 batched | Fully redacted per-window | Fully redacted batched | p50 / p99 ms per-window | p50 / p99 ms batched |
| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| presidio-research | 0.0131 | 0.0136 | +3% | 0.718 | 0.719 | 0.500 | 0.500 | 7 / 27 | 7 / 29 |
| ai4privacy | 0.0203 | 0.0195 | −4% | 0.576 | 0.577 | 0.338 | 0.338 | 17 / 74 | 15 / 92 |
| secrets | 0.105 | 0.0888 | −16% | 0.636 | 0.636 | 0.542 | 0.542 | 0 / 17 | 0 / 18 |
| RedactionBench | 0.0316 | 0.0292 | −8% | 0.611 | 0.618 | 0.608 | 0.608 | 156 / 7,965 | 232 / 7,876 |
| CoNLL | 0.00744 | 0.00983 | +32% | 0.796 | 0.794 | 0.648 | 0.645 | 70 / 535 | 70 / 453 |

Speed moves in both directions, from −16% to +32%, and accuracy moves by at most
0.007 F1. The deterministic default therefore costs nothing measurable. An earlier
small-sample check suggested per-window was 1.2–1.5× faster; the full run does not
support that.

## 7. Status against the success criteria (dev, Phase 0)

| Criterion | Target | Now (dev) | Met? |
| --- | --- | --- | --- |
| Pattern tier, RedactionBench char P / R | P ≥ 0.75, R ≥ 0.60 | 0.730 / 0.449 | no |
| NER entity recall (fully redacted) vs best Presidio, non-overlapping CIs | ≥ Presidio | presidio-research 0.500 vs 0.545; ai4privacy 0.338 vs 0.607; secrets 0.542 vs 0.735 | no |
| NER char recall | ≥ 0.70 | 0.456–0.577 on the headline sets | no |
| NER memory ≤ Presidio | ≤ Presidio | 150 MB vs `sm` 127–205, `lg` 703+, transformers 766+ | vs `sm`: mixed; vs `lg` and transformers: yes |
| NER throughput | ≥ 5× `presidio-sm`, ≥ 0.5 MB/s per core | 0.32–4.7×; 0.007–0.10 MB/s | no |
| Native single core | ≥ 25 MB/s | 3.0–16.6 MB/s (power-saving mode; re-measure in Best performance) | no |
| Native scaling | near-linear to physical cores | not yet measured (Phase 3) | — |
| RedactionBench mandatory recall (T0 + model) | ≥ 0.92 | 0.875 [0.761, 0.936] (previously exposed) | no |
| RedactionBench no-leak documents | ≥ 50% | 17.0% | no |
| Credentials | keep the lead; ≥ 200 real-format secrets | 426 secrets; fully redacted 54.2% vs Presidio-regex 13.1%, but Presidio-trf-deid reaches 73.5% while flagging every negative | corpus yes; lead over trf-deid no |
| Beat or match Presidio on ≥ 2 independent corpora | 2 | char F1 matches the best Presidio on presidio-research and secrets (CIs overlap); loses on ai4privacy | no |

## 8. Phase 1 targets, ranked

Ranked by expected gain on the headline dev sets per unit of risk. Each change lands
with before/after dev numbers. Any trade of precision for recall comes back to you for
a decision.

1. **Entropy false alarms (secrets FP-document rate 0.806).** UUIDs, commit SHAs,
   SHA-256 digests in hash contexts, and `data:` image URIs are flagged as secrets.
   Demote these shapes in the entropy tier unless a secret-like key precedes them.
2. **Structured-field context.** Use JSON keys, XML tags, YAML keys and `Label:` lines
   (`LastName`, `Phone`, `Postcode`, `Driver's License`, `ID`) to type the value that
   follows. This is the largest recall lever on ai4privacy (ID, PERSON, LOCATION,
   PHONE), and it is generic, not tied to one corpus's templates.
3. **Secret assignments and connection strings** (50 of the 119 secret leaks):
   - the value after a secret-like key, through `=`, `=>`, `:` or XML `value="…"`,
     letters-only values included;
   - `Password=`, `Pwd=` and `Secret=` in ADO, ODBC and Azure connection strings;
   - every URI scheme with `user:pass@`.
4. **Phones.** First find why `618-226-1460` after "messages to" is missed. Then add
   international, dotted and grouped formats with E.164-aware validation (recall is
   0.56–0.59 today).
5. **Vendor keys, full-span tokens and password hashes** (52 leaks):
   - new vendor families: Auth0, Heroku, Mailgun, Postmark, Shopify, New Relic,
     LinkedIn and others;
   - Doppler, Dropbox, Dynatrace and Azure tokens covered end to end;
   - password hashes as whole spans: bcrypt, argon2, scrypt, PBKDF2, crypt(3), Cisco,
     Kerberos.
6. **URL and IBAN in the default tier**, and the fix for the Ethereum address that is
   flagged as a credit-card fragment.
7. **Label-anchored IDs.** Driver's licence, passport and ID card, plus US ITIN,
   passport and bank number for Presidio parity; checksum-validated national IDs where
   a checksum exists.
8. **Dates and NRP.** Making the date tier default-on is a precision trade-off: it wins
   on ai4privacy but misses years and weekdays on presidio-research. Nationality
   adjectives come from a fixed list.
9. **Contextual-tier rework** (the `test` substring suppression, CODE_REVIEW F1) and
   non-US street lines.
10. **Harness:** pass texts to the child processes so ai4privacy memory becomes
    measurable.

Names (sentence-initial, lowercase, signature lines) and the NER memory and throughput
targets belong to Phase 2.
