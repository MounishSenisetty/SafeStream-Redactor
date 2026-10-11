## presidio_research / dev (750 docs)

2026-10-04T18:04:21+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (23%) | Python 3.14.0 | commit c6a1548f52

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | Char F1 (Presidio-scope) | Fully redacted (Presidio-scope) | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native-onnx | ner | 0.951 [0.938, 0.964] | 0.588 [0.557, 0.620] | 0.727 [0.703, 0.751] | 0.511 [0.476, 0.545] | 0.647 [0.617, 0.676] | 0.565 [0.532, 0.597] | 0.080 [0.018, 0.167] | 0.734 [0.710, 0.758] | 0.538 [0.501, 0.575] | 0.0121 | 7.4 / 28.6 | 1.8 | 185 / 159 |
| safestream-native-onnx-prose | ner | 0.953 [0.941, 0.965] | 0.643 [0.613, 0.673] | 0.768 [0.746, 0.790] | 0.557 [0.521, 0.591] | 0.680 [0.653, 0.709] | 0.600 [0.569, 0.631] | 0.080 [0.018, 0.167] | 0.775 [0.753, 0.798] | 0.586 [0.549, 0.625] | 0.0122 | 7.3 / 29.8 | 0.6 | 185 / 160 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native-onnx | safestream-native-onnx-prose |
|---|---|---|---|
| AGE | 42 | 0.00 / 0.00 | 0.00 / 0.00 |
| CREDIT_CARD | 71 | 0.99 / 0.93 | 0.99 / 0.93 |
| DATE_TIME | 59 | 1.00 / 0.05 | 1.00 / 0.37 |
| EMAIL_ADDRESS | 28 | 1.00 / 1.00 | 1.00 / 1.00 |
| IBAN_CODE | 7 | 1.00 / 1.00 | 1.00 / 1.00 |
| ID | 2 | 1.00 / 0.50 | 1.00 / 0.50 |
| IP_ADDRESS | 12 | 1.00 / 1.00 | 1.00 / 1.00 |
| LOCATION | 564 | 0.59 / 0.28 | 0.58 / 0.27 |
| NRP | 27 | 0.00 / 0.00 | 0.51 / 0.93 |
| ORGANIZATION | 122 | 0.52 / 0.63 | 0.52 / 0.63 |
| PERSON | 418 | 0.88 / 0.84 | 0.88 / 0.84 |
| PHONE_NUMBER | 39 | 1.00 / 0.72 | 1.00 / 0.72 |
| TITLE | 49 | 0.00 / 0.00 | 0.00 / 0.00 |
| URL | 19 | 0.00 / 0.00 | 1.00 / 1.00 |
| US_SSN | 10 | 1.00 / 1.00 | 1.00 / 1.00 |
