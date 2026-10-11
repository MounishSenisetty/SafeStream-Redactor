## secrets / dev (313 docs)

2026-10-03T21:44:03+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit 52372c76c0

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.888 [0.839, 0.928] | 0.814 [0.761, 0.860] | 0.849 [0.807, 0.885] | 0.542 [0.481, 0.606] | 0.714 [0.674, 0.756] | 0.509 [0.450, 0.570] | 0.000 [0.000, 0.000] | 3.86 | 0.0 / 0.2 | 0.1 | 59 / 34 |
| safestream-native-prose | pattern | 0.886 [0.838, 0.927] | 0.814 [0.761, 0.860] | 0.849 [0.806, 0.884] | 0.542 [0.481, 0.606] | 0.713 [0.671, 0.755] | 0.508 [0.449, 0.570] | 0.000 [0.000, 0.000] | 2.76 | 0.0 / 0.2 | 0.1 | 59 / 34 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.119 | 0.8 / 5.6 | 1.2 | 105 / 80 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.85 / 0.64 | 0.85 / 0.64 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
