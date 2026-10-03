## secrets / dev (313 docs)

2026-10-03T22:44:29+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (90%) | Python 3.14.0 | commit 9d87212b36

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.910 [0.866, 0.948] | 0.835 [0.782, 0.880] | 0.871 [0.832, 0.904] | 0.696 [0.645, 0.750] | 0.802 [0.767, 0.836] | 0.682 [0.632, 0.734] | 0.000 [0.000, 0.000] | 1.45 | 0.1 / 0.4 | 0.1 | 59 / 34 |
| safestream-native-prose | pattern | 0.909 [0.864, 0.947] | 0.835 [0.782, 0.880] | 0.870 [0.831, 0.904] | 0.696 [0.645, 0.750] | 0.801 [0.765, 0.835] | 0.681 [0.629, 0.732] | 0.000 [0.000, 0.000] | 1.24 | 0.1 / 0.4 | 0.1 | 59 / 33 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.14 | 0.7 / 4.6 | 1.2 | 105 / 80 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.87 / 0.74 | 0.87 / 0.74 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
