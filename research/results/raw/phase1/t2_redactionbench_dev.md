## redactionbench / dev (100 docs)

2026-10-03T22:03:16+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit 5bf701b1dc

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.690 [0.490, 0.844] | 0.455 [0.397, 0.559] | 0.549 [0.455, 0.624] | 0.545 [0.367, 0.667] | 0.201 [0.165, 0.227] | 0.040 [0.028, 0.053] | 0.826 [0.667, 0.909] | 0.096 [0.043, 0.158] | 7.85 | 1.0 / 22.7 | 0.1 | 71 / 43 |
| safestream-native-prose | pattern | 0.582 [0.398, 0.750] | 0.474 [0.414, 0.586] | 0.523 [0.435, 0.588] | 0.614 [0.467, 0.711] | 0.206 [0.179, 0.228] | 0.037 [0.026, 0.050] | 0.832 [0.680, 0.913] | 0.096 [0.043, 0.158] | 3.96 | 1.7 / 42.0 | 0.1 | 71 / 44 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0541 | 75.5 / 5142.2 | 1.0 | 111 / 83 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
