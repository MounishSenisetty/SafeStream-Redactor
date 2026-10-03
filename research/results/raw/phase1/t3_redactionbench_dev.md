## redactionbench / dev (100 docs)

2026-10-03T22:21:07+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit e0474cc363

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.700 [0.502, 0.850] | 0.457 [0.399, 0.562] | 0.553 [0.461, 0.630] | 0.546 [0.369, 0.668] | 0.202 [0.165, 0.227] | 0.045 [0.033, 0.061] | 0.831 [0.674, 0.911] | 0.117 [0.062, 0.185] | 3.35 | 2.2 / 65.2 | 0.1 | 71 / 43 |
| safestream-native-prose | pattern | 0.590 [0.406, 0.758] | 0.476 [0.415, 0.589] | 0.527 [0.440, 0.594] | 0.615 [0.468, 0.712] | 0.206 [0.180, 0.229] | 0.042 [0.030, 0.057] | 0.837 [0.687, 0.915] | 0.117 [0.062, 0.185] | 2.34 | 2.8 / 86.9 | 0.1 | 71 / 44 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0654 | 72.5 / 3768.2 | 0.9 | 111 / 84 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
