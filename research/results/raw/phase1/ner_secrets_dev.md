## secrets / dev (313 docs)

2026-10-04T18:10:09+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (18%) | Python 3.14.0 | commit c6a1548f52

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native-onnx | ner | 0.907 [0.867, 0.942] | 0.901 [0.860, 0.935] | 0.904 [0.872, 0.931] | 0.812 [0.767, 0.857] | 0.819 [0.786, 0.851] | 0.781 [0.742, 0.819] | 0.010 [0.000, 0.033] | 0.068 | 0.2 / 24.4 | 0.7 | 185 / 159 |
| safestream-native-onnx-prose | ner | 0.811 [0.754, 0.860] | 0.907 [0.865, 0.940] | 0.856 [0.817, 0.890] | 0.819 [0.774, 0.864] | 0.770 [0.737, 0.804] | 0.727 [0.689, 0.764] | 0.010 [0.000, 0.033] | 0.0672 | 0.3 / 22.7 | 0.7 | 185 / 159 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native-onnx | safestream-native-onnx-prose |
|---|---|---|---|
| SECRET | 260 | 0.91 / 0.75 | 0.91 / 0.75 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
