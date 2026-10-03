## secrets / dev (313 docs)

2026-10-03T21:38:40+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit e5fbc27303

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.524 [0.438, 0.609] | 0.814 [0.761, 0.860] | 0.637 [0.560, 0.706] | 0.542 [0.481, 0.606] | 0.609 [0.567, 0.651] | 0.434 [0.380, 0.489] | 0.806 [0.729, 0.880] | 3.81 | 0.0 / 0.2 | 0.1 | 59 / 33 |
| safestream-native-prose | pattern | 0.523 [0.438, 0.609] | 0.814 [0.761, 0.860] | 0.637 [0.560, 0.706] | 0.542 [0.481, 0.606] | 0.607 [0.565, 0.650] | 0.433 [0.380, 0.488] | 0.806 [0.729, 0.880] | 2.76 | 0.0 / 0.3 | 0.1 | 59 / 34 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.134 | 0.7 / 4.7 | 1.3 | 105 / 79 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.60 / 0.64 | 0.60 / 0.64 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
