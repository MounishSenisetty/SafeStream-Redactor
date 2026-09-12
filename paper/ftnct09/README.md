# FTNCT'09 paper — SafeStream-Redactor

Submission-ready LaTeX source for FTNCT'09, Track 4 (Cybersecurity, Privacy, and
Trust). FTNCT proceedings are published by Springer in the *Communications in
Computer and Information Science* (CCIS) series, which uses the official Springer
LNCS author template (`llncs.cls`), single-column A4, numbered references.

## Build

```bash
pdflatex safestream-redactor-ftnct09.tex
pdflatex safestream-redactor-ftnct09.tex   # second pass resolves \ref/\cite
```

The bibliography is embedded as a `thebibliography` block, so no BibTeX run is
required. Required classes/packages: `llncs`, `tikz`/`pgf`, `algorithm`,
`algorithmicx` (`algpseudocode`), `booktabs`, `makecell`, `microtype`,
`hyperref` (all in a standard TeX Live). Output: 15 pages, no undefined
references, no bibliography errors.

## Source of truth

Every number, claim, and figure is drawn only from this repository. Key sources:

- Formal model, constants, theorems: `docs/FORMAL_MODEL.md`, `src/.../engine.py`,
  `parallel.py`, `detectors/{deterministic,entropy,contextual}.py`, `detectors/base.py`.
- Measured accuracy/throughput: `research/results/processed/accuracy.md`
  (raw: `research/results/raw/accuracy_2026-08-16.json`).
- Constant-memory scaling: `research/results/processed/memory.md`
  (raw: `research/results/raw/memory_2026-08-16.json`), plus the 1 GB
  `pytest -m memory` test.
- Prior Presidio comparison, prefilter (~25×) and parallel (~3.7×) figures:
  top-level `README.md`, `research/reports/benchmark-report.md`.
- Capability matrix (documented, not measured): `research/comparisons/README.md`,
  `research/results/tables/competitor-comparison.{md,csv}`.
- Calibration / ensemble / NER / ONNX interface: `src/.../calibration.py`,
  `benchmarks/{calibrate,evaluate}.py`, `detectors/{ner,onnx_ner}.py`.

The author block is a placeholder to be completed at camera-ready time.
