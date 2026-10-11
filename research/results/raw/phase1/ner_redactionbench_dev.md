## redactionbench / dev (100 docs)

2026-10-04T18:10:15+05:30 | 12th Gen Intel(R) Core(TM) i7-12650H (10C/16T) | power: BATTERY (18%) | Python 3.14.0 | commit c6a1548f52

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| safestream-native-onnx | ner | 0.683 [0.497, 0.826] | 0.554 [0.500, 0.654] | 0.611 [0.522, 0.673] | 0.618 [0.474, 0.714] | 0.237 [0.214, 0.268] | 0.069 [0.051, 0.096] | 0.887 [0.783, 0.943] | 0.234 [0.151, 0.323] | 0.0135 | 366.9 / 19887.7 | 0.7 | 203 / 175 |
| safestream-native-onnx-prose | ner | 0.543 [0.408, 0.650] | 0.582 [0.519, 0.697] | 0.562 [0.485, 0.623] | 0.693 [0.583, 0.764] | 0.237 [0.211, 0.275] | 0.064 [0.047, 0.092] | 0.899 [0.808, 0.950] | 0.234 [0.151, 0.323] | 0.0132 | 388.5 / 20224.6 | 0.8 | 206 / 178 |

Per type (partial-match entity P / R, gold count):

| Type | Gold | safestream-native-onnx | safestream-native-onnx-prose |
|---|---|---|---|
| SENSITIVE | 27694 | 0.00 / 0.00 | 0.00 / 0.00 |
