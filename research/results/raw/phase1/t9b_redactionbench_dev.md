## redactionbench / dev (100 docs)

2026-10-04T18:03:06+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (25%) | Python 3.14.0 | commit 755b41fa6f

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.700 [0.502, 0.850] | 0.460 [0.401, 0.567] | 0.555 [0.466, 0.633] | 0.548 [0.373, 0.670] | 0.204 [0.168, 0.230] | 0.046 [0.034, 0.062] | 0.836 [0.684, 0.915] | 0.128 [0.065, 0.198] | 1.97 | 3.6 / 100.0 | 0.2 | 79 / 51 |
| safestream-native-prose | pattern | 0.532 [0.395, 0.643] | 0.489 [0.425, 0.608] | 0.510 [0.437, 0.584] | 0.624 [0.482, 0.719] | 0.207 [0.184, 0.231] | 0.043 [0.031, 0.059] | 0.848 [0.712, 0.920] | 0.128 [0.065, 0.198] | 0.818 | 8.0 / 247.7 | 0.2 | 80 / 53 |
| presidio-regex | pattern | 0.356 [0.250, 0.453] | 0.310 [0.268, 0.393] | 0.331 [0.289, 0.372] | 0.545 [0.397, 0.652] | 0.208 [0.178, 0.235] | 0.043 [0.026, 0.063] | 0.359 [0.259, 0.427] | 0.011 [0.000, 0.033] | 0.0711 | 64.9 / 3457.9 | 1.2 | 111 / 83 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
