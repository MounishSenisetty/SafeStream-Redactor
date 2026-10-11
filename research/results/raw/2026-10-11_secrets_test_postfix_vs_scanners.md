## secrets / test (313 docs)

2026-10-11T09:12:36+00:00 | Intel(R) Xeon(R) Processor @ 2.80GHz (4C/4T) | power: no battery (AC) | Python 3.13.16 | commit f10b9588a9

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.857 [0.705, 0.946] | 0.829 [0.740, 0.887] | 0.842 [0.736, 0.906] | 0.437 [0.384, 0.498] | 0.586 [0.522, 0.651] | 0.419 [0.361, 0.485] | 0.010 [0.000, 0.035] | 2.82 | 0.0 / 0.3 | 0.1 | 54 / 32 |
| safestream-native-spacy | ner | 0.757 [0.604, 0.858] | 0.845 [0.762, 0.897] | 0.799 [0.683, 0.870] | 0.488 [0.435, 0.548] | 0.534 [0.481, 0.589] | 0.364 [0.315, 0.416] | 0.340 [0.250, 0.438] | 0.0281 | 4.9 / 12.4 | 1.1 | 170 / 147 |
| gitleaks | pattern | 0.837 [0.630, 0.962] | 0.473 [0.299, 0.679] | 0.604 [0.430, 0.765] | 0.311 [0.253, 0.375] | 0.455 [0.389, 0.521] | 0.430 [0.364, 0.498] | 0.000 [0.000, 0.000] | 0.267 | 0.6 / 0.6 | 0.0 | n/a (external binary) |
| trufflehog | pattern | 0.803 [0.719, 0.878] | 0.189 [0.117, 0.308] | 0.306 [0.204, 0.446] | 0.270 [0.204, 0.340] | 0.325 [0.266, 0.381] | 0.249 [0.190, 0.308] | 0.000 [0.000, 0.000] | 0.0217 | 6.9 / 6.9 | 0.0 | n/a (external binary) |
| presidio-lg | ner | 0.308 [0.238, 0.381] | 0.131 [0.082, 0.214] | 0.184 [0.124, 0.262] | 0.164 [0.116, 0.212] | 0.081 [0.056, 0.116] | 0.021 [0.011, 0.034] | 0.433 [0.337, 0.530] | 0.0153 | 8.0 / 32.0 | 4.3 | 763 / 740 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-spacy | gitleaks | trufflehog | presidio-lg |
|---|---|---|---|---|---|---|
| SECRET | 293 | 0.72 / 0.49 | 0.72 / 0.50 | 0.85 / 0.31 | 0.79 / 0.20 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
