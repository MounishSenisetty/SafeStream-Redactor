## secrets / dev (313 docs)

2026-10-11T09:00:29+00:00 | Intel(R) Xeon(R) Processor @ 2.80GHz (4C/4T) | power: no battery (AC) | Python 3.13.16 | commit 0765daeddd (dirty)

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | FP doc rate | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gitleaks | pattern | 0.938 [0.892, 0.975] | 0.417 [0.321, 0.522] | 0.578 [0.479, 0.671] | 0.396 [0.335, 0.465] | 0.531 [0.470, 0.594] | 0.504 [0.439, 0.569] | 0.000 [0.000, 0.000] | 0.473 | 0.3 / 0.3 | 0.0 | n/a (external binary) |
| trufflehog | pattern | 0.905 [0.839, 0.960] | 0.194 [0.129, 0.271] | 0.320 [0.224, 0.418] | 0.165 [0.117, 0.221] | 0.245 [0.182, 0.307] | 0.220 [0.158, 0.280] | 0.000 [0.000, 0.000] | 0.0204 | 6.6 / 6.6 | 0.0 | n/a (external binary) |

Per type (partial-match entity P / R, gold count):

| Type | Gold | gitleaks | trufflehog |
|---|---|---|---|
| SECRET | 260 | 0.88 / 0.38 | 0.67 / 0.15 |

Loader notes: 2 gold item(s) adjusted or unplaceable (listed in the JSON).
