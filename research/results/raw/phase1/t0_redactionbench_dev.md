## redactionbench / dev (100 docs)

2026-10-03T21:38:47+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit e5fbc27303

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.730 [0.555, 0.860] | 0.449 [0.391, 0.550] | 0.556 [0.479, 0.622] | 0.534 [0.355, 0.659] | 0.200 [0.163, 0.224] | 0.036 [0.026, 0.049] | 0.818 [0.655, 0.904] | 0.096 [0.043, 0.158] | 13.3 | 0.6 / 14.8 | 0.1 | 70 / 43 |
| safestream-native-prose | pattern | 0.609 [0.431, 0.764] | 0.468 [0.409, 0.577] | 0.529 [0.451, 0.590] | 0.603 [0.453, 0.705] | 0.204 [0.180, 0.224] | 0.034 [0.024, 0.046] | 0.824 [0.667, 0.909] | 0.096 [0.043, 0.158] | 4.72 | 1.5 / 36.2 | 0.2 | 71 / 43 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0444 | 114.7 / 6131.6 | 1.3 | 111 / 84 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
