## redactionbench / test (100 docs)

2026-10-11T09:13:19+00:00 | Intel(R) Xeon(R) Processor @ 2.80GHz (4C/4T) | power: no battery (AC) | Python 3.13.16 | commit f10b9588a9

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.831 [0.770, 0.884] | 0.444 [0.350, 0.547] | 0.579 [0.490, 0.662] | 0.516 [0.308, 0.675] | 0.182 [0.144, 0.221] | 0.047 [0.026, 0.077] | 0.682 [0.578, 0.787] | 0.084 [0.032, 0.144] | 11.7 | 0.8 / 12.6 | 0.2 | 171 / 35 |
| safestream-native-spacy | ner | 0.485 [0.378, 0.595] | 0.541 [0.447, 0.640] | 0.512 [0.429, 0.590] | 0.582 [0.395, 0.727] | 0.184 [0.152, 0.223] | 0.053 [0.036, 0.079] | 0.761 [0.657, 0.860] | 0.179 [0.105, 0.263] | 0.0528 | 120.0 / 4939.9 | 1.2 | 777 / 640 |
| gitleaks | pattern | 0.992 [0.981, 0.998] | 0.120 [0.070, 0.187] | 0.214 [0.130, 0.314] | 0.010 [0.005, 0.018] | 0.018 [0.009, 0.032] | 0.017 [0.009, 0.030] | 0.247 [0.140, 0.372] | 0.021 [0.000, 0.053] | 1.94 | 7.1 / 7.1 | 0.0 | n/a (external binary) |
| trufflehog | pattern | 0.919 [0.799, 1.000] | 0.015 [0.009, 0.025] | 0.030 [0.017, 0.048] | 0.002 [0.001, 0.004] | 0.004 [0.002, 0.007] | 0.002 [0.001, 0.005] | 0.024 [0.013, 0.040] | 0.000 [0.000, 0.000] | 0.552 | 25.0 / 25.0 | 0.0 | n/a (external binary) |
| presidio-lg | ner | 0.291 [0.213, 0.379] | 0.422 [0.364, 0.479] | 0.344 [0.277, 0.409] | 0.604 [0.497, 0.674] | 0.215 [0.175, 0.259] | 0.065 [0.042, 0.095] | 0.420 [0.333, 0.499] | 0.105 [0.052, 0.174] | 0.02 | 305.6 / 9691.7 | 4.7 | 947 / 810 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-spacy | gitleaks | trufflehog | presidio-lg |
|---|---|---|---|---|---|---|
| SENSITIVE | 25592 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
