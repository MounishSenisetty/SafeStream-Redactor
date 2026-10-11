## ai4privacy / dev (3973 docs)

2026-10-04T18:04:35+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (23%) | Python 3.14.0 | commit c6a1548f52

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | Char F1 (Presidio-scope) | Fully redacted (Presidio-scope) | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native-onnx | ner | 0.821 [0.812, 0.830] | 0.641 [0.630, 0.653] | 0.720 [0.711, 0.729] | 0.563 [0.551, 0.576] | 0.642 [0.633, 0.652] | 0.591 [0.579, 0.602] | 0.473 [0.428, 0.518] | 0.741 [0.733, 0.750] | 0.613 [0.601, 0.626] | 0.0166 | 20.1 / 98.1 | 0.6 | 198 / 170 |
| safestream-native-onnx-prose | ner | 0.832 [0.824, 0.841] | 0.741 [0.730, 0.751] | 0.784 [0.776, 0.791] | 0.672 [0.660, 0.683] | 0.721 [0.713, 0.730] | 0.674 [0.664, 0.685] | 0.496 [0.449, 0.540] | 0.803 [0.796, 0.810] | 0.721 [0.710, 0.732] | 0.00776 | 41.5 / 211.0 | 0.6 | 198 / 171 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native-onnx | safestream-native-onnx-prose |
|---|---|---|---|
| DATE_TIME | 3906 | 0.96 / 0.14 | 0.92 / 0.72 |
| EMAIL_ADDRESS | 1353 | 0.97 / 1.00 | 0.97 / 1.00 |
| ID | 5003 | 0.97 / 0.43 | 0.97 / 0.43 |
| IP_ADDRESS | 1084 | 0.98 / 0.98 | 0.98 / 0.98 |
| LOCATION | 6180 | 0.81 / 0.63 | 0.81 / 0.63 |
| PERSON | 2978 | 0.72 / 0.53 | 0.72 / 0.53 |
| PHONE_NUMBER | 991 | 0.81 / 0.73 | 0.81 / 0.73 |
| SECRET | 772 | 0.95 / 0.54 | 0.95 / 0.54 |
| SEX | 1035 | 0.00 / 0.00 | 0.96 / 0.44 |
| TITLE | 929 | 0.00 / 0.00 | 0.00 / 0.00 |
| USERNAME | 1375 | 0.93 / 0.37 | 0.93 / 0.37 |

Loader notes: 1 gold item(s) adjusted or unplaceable (listed in the JSON).
