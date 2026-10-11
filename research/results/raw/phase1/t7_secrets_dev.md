## secrets / dev (313 docs)

2026-10-04T00:08:12+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (26%) | Python 3.14.0 | commit d737fea5c3

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native | pattern | 0.918 [0.880, 0.951] | 0.899 [0.859, 0.934] | 0.909 [0.879, 0.935] | 0.808 [0.764, 0.853] | 0.837 [0.805, 0.868] | 0.794 [0.754, 0.832] | 0.000 [0.000, 0.000] | 1.04 | 0.1 / 0.7 | 0.2 | 69 / 44 |
| safestream-native-prose | pattern | 0.825 [0.767, 0.874] | 0.905 [0.863, 0.939] | 0.863 [0.826, 0.897] | 0.815 [0.770, 0.860] | 0.790 [0.758, 0.823] | 0.742 [0.703, 0.779] | 0.000 [0.000, 0.000] | 0.916 | 0.1 / 0.7 | 0.2 | 69 / 44 |
| presidio-regex | pattern | 0.292 [0.210, 0.378] | 0.171 [0.115, 0.242] | 0.215 [0.152, 0.287] | 0.131 [0.091, 0.173] | 0.055 [0.037, 0.083] | 0.029 [0.016, 0.047] | 0.427 [0.333, 0.522] | 0.145 | 0.7 / 4.1 | 1.1 | 105 / 80 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native | safestream-native-prose | presidio-regex |
|---|---|---|---|---|
| SECRET | 260 | 0.91 / 0.75 | 0.91 / 0.75 | 0.00 / 0.00 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
