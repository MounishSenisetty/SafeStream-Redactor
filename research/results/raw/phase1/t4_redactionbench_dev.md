## redactionbench / dev (100 docs)

2026-10-03T22:44:34+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (90%) | Python 3.14.0 | commit 9d87212b36

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.700 [0.502, 0.850] | 0.458 [0.400, 0.563] | 0.554 [0.462, 0.630] | 0.548 [0.371, 0.670] | 0.203 [0.166, 0.228] | 0.045 [0.033, 0.061] | 0.831 [0.675, 0.912] | 0.117 [0.062, 0.185] | 2.97 | 2.4 / 72.5 | 0.1 | 70 / 43 |
| safestream-native-prose | pattern | 0.590 [0.406, 0.758] | 0.476 [0.416, 0.591] | 0.527 [0.440, 0.594] | 0.617 [0.472, 0.714] | 0.207 [0.180, 0.230] | 0.042 [0.030, 0.057] | 0.837 [0.688, 0.916] | 0.117 [0.062, 0.185] | 2.08 | 3.4 / 95.0 | 0.1 | 71 / 44 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.014 | 255.1 / 19104.7 | 1.1 | 111 / 83 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
