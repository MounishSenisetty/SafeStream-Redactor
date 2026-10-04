## redactionbench / dev (100 docs)

2026-10-04T00:32:00+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit ac43d08405

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.701 [0.502, 0.850] | 0.460 [0.401, 0.567] | 0.555 [0.466, 0.633] | 0.548 [0.373, 0.670] | 0.204 [0.168, 0.230] | 0.046 [0.034, 0.062] | 0.836 [0.684, 0.915] | 0.117 [0.062, 0.185] | 2.4 | 2.9 / 82.1 | 0.1 | 79 / 52 |
| safestream-native-prose | pattern | 0.532 [0.395, 0.643] | 0.489 [0.425, 0.607] | 0.510 [0.437, 0.584] | 0.624 [0.481, 0.719] | 0.207 [0.184, 0.231] | 0.043 [0.031, 0.059] | 0.848 [0.711, 0.920] | 0.117 [0.062, 0.185] | 1 | 6.4 / 206.2 | 0.1 | 79 / 52 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0599 | 78.4 / 4553.9 | 1.0 | 111 / 83 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
