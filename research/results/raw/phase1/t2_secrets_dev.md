## secrets / dev (313 docs)

2026-10-03T22:03:13+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: AC | Python 3.14.0 | commit 5bf701b1dc

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.888 [0.839, 0.929] | 0.816 [0.763, 0.862] | 0.850 [0.808, 0.885] | 0.550 [0.489, 0.615] | 0.719 [0.678, 0.760] | 0.516 [0.457, 0.576] | 0.000 [0.000, 0.000] | 2.92 | 0.0 / 0.2 | 0.1 | 59 / 34 |
| safestream-native-prose | pattern | 0.887 [0.838, 0.927] | 0.816 [0.763, 0.862] | 0.850 [0.807, 0.885] | 0.550 [0.489, 0.615] | 0.718 [0.677, 0.759] | 0.515 [0.456, 0.575] | 0.000 [0.000, 0.000] | 2.31 | 0.0 / 0.2 | 0.1 | 59 / 34 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.16 | 0.6 / 4.0 | 1.0 | 105 / 80 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.85 / 0.64 | 0.85 / 0.64 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
