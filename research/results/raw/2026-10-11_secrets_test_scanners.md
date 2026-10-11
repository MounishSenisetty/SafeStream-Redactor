## secrets / test (313 docs)

2026-10-11T09:00:50+00:00 | Intel(R) Xeon(R) Processor @ 2.80GHz (4C/4T) | power: no battery (AC) | Python 3.13.16 | commit 0765daeddd (dirty)

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gitleaks | pattern | 0.837 [0.630, 0.962] | 0.473 [0.299, 0.679] | 0.604 [0.430, 0.765] | 0.311 [0.253, 0.375] | 0.455 [0.389, 0.521] | 0.430 [0.364, 0.498] | 0.000 [0.000, 0.000] | 0.417 | 0.4 / 0.4 | 0.0 | n/a (external binary) |
| trufflehog | pattern | 0.803 [0.719, 0.878] | 0.189 [0.117, 0.308] | 0.306 [0.204, 0.446] | 0.270 [0.204, 0.340] | 0.325 [0.266, 0.381] | 0.249 [0.190, 0.308] | 0.000 [0.000, 0.000] | 0.0223 | 6.7 / 6.7 | 0.0 | n/a (external binary) |

Per type (partial-match entity P / R, gold count):

| Type | Gold | gitleaks | trufflehog |
|---|---|---|---|
| SECRET | 293 | 0.85 / 0.31 | 0.79 / 0.20 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
