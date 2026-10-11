## redactionbench / test (100 docs)

2026-10-11T09:01:05+00:00 | Intel(R) Xeon(R) Processor @ 2.80GHz (4C/4T) | power: no battery (AC) | Python 3.13.16 | commit 0765daeddd (dirty)

> **Previously exposed:** all 200 documents were used for error analysis and rule tuning before 2026-10-03; its test half is reported as 'previously exposed', not held out

| System | Tier | Char P | Char R | Char F1 | Entity R (covered) | Ent F1 partial | Ent F1 strict | Mandatory R | No-leak docs | MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gitleaks | pattern | 0.992 [0.981, 0.998] | 0.120 [0.070, 0.187] | 0.214 [0.130, 0.314] | 0.010 [0.005, 0.018] | 0.018 [0.009, 0.032] | 0.017 [0.009, 0.030] | 0.247 [0.140, 0.372] | 0.021 [0.000, 0.053] | 3.26 | 4.2 / 4.2 | 0.0 | n/a (external binary) |
| trufflehog | pattern | 0.919 [0.799, 1.000] | 0.015 [0.009, 0.025] | 0.030 [0.017, 0.048] | 0.002 [0.001, 0.004] | 0.004 [0.002, 0.007] | 0.002 [0.001, 0.005] | 0.024 [0.013, 0.040] | 0.000 [0.000, 0.000] | 0.615 | 22.4 / 22.4 | 0.0 | n/a (external binary) |

Per type (partial-match entity P / R, gold count):

| Type | Gold | gitleaks | trufflehog |
|---|---|---|---|
| SENSITIVE | 25592 | 0.00 / 0.00 | 0.00 / 0.00 |
