## secrets / dev (313 docs)

2026-10-04T18:03:02+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (25%) | Python 3.14.0 | commit 755b41fa6f

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.916 [0.879, 0.949] | 0.901 [0.860, 0.935] | 0.909 [0.878, 0.935] | 0.812 [0.767, 0.857] | 0.837 [0.804, 0.868] | 0.798 [0.760, 0.835] | 0.000 [0.000, 0.000] | 0.799 | 0.1 / 1.0 | 0.2 | 69 / 44 |
| safestream-native-prose | pattern | 0.818 [0.760, 0.866] | 0.907 [0.865, 0.940] | 0.860 [0.822, 0.894] | 0.819 [0.774, 0.864] | 0.784 [0.752, 0.818] | 0.740 [0.704, 0.778] | 0.000 [0.000, 0.000] | 0.572 | 0.2 / 0.9 | 0.2 | 69 / 44 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.139 | 0.7 / 4.3 | 1.3 | 105 / 80 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.91 / 0.75 | 0.91 / 0.75 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
