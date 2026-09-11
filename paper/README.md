# SafeStream-Redactor — Research Paper

IEEE conference paper on the core research architecture: provably-equivalent
bounded-memory streaming redaction of PII and credentials.

## Files
- `main.tex` — the paper (IEEEtran, self-contained; TikZ figures and algorithms inline).
- `references.bib` — bibliography (real, verifiable sources only).
- `main.pdf` — compiled output (7 pages).

## Compile
Overleaf: upload `main.tex` + `references.bib`, set the compiler to pdfLaTeX, build.

Locally (TeX Live with `texlive-latex-extra`, `texlive-pictures`,
`texlive-publishers`, `texlive-science`):

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

## Where every number comes from
All experimental values are produced by running the repository's own harnesses;
none are copied from prior documents.

| Paper item | Value | Produced by |
| --- | --- | --- |
| Precision / Recall / F1 (Table II) | 1.000 / 1.000 / 1.000 (fp=0, fn=0, 60 253 gold) | `benchmarks/run_benchmark.py` |
| Single-core throughput | ~3.76 MB/s (this run) | `benchmarks/run_benchmark.py` |
| Boundary ablation (Table III) | naive 251/251 incorrect (75 verbatim leaks); overlap-safe 0/251 | `benchmarks/paper_experiments.py boundary` |
| Tier ablation (Table IV) | entropy/contextual contributions | `benchmarks/paper_experiments.py tiers` |
| Credential coverage | 9/9 classes | `benchmarks/paper_experiments.py coverage` |
| Parallel speedup + byte-identity (Table V) | 1.95× / 3.58×, byte-identical (SHA-256) | `benchmarks/paper_experiments.py parallel` |
| Constant memory (Table VI) | 0.66 / 0.65 / 0.65 MB at 16/32/64 MB | `benchmarks/paper_experiments.py memory` |
| 1 GB peak memory | < 16 MB | `SAFESTREAM_MEMTEST_MB=1024 pytest tests/test_memory.py -m memory -o addopts=''` |
| Constants C_left=48, C_right=2, L_max=8192 | audited from code | `docs/FORMAL_MODEL.md` §3 |

## Not verified in-paper (stated as such)
- No external third-party labeled corpus is evaluated (none is bundled); F1=1.000 is on synthetic data only.
- Absolute throughput reflects a shared 4-vCPU container; it is a shape/ratio result, not a line-rate claim.
- Presidio is cited conceptually (PII-only, no credentials); no head-to-head Presidio benchmark is run here (the `[bench]` extra is not installed in the measurement environment).
