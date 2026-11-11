# Journal manuscript (International Journal of Information Security, Springer)

Springer Nature LaTeX template (`sn-jnl.cls`, numbered references with
`sn-mathphys-num.bst`). The Computers & Security version is kept in `../journal/`.

## Build

    pdflatex main && bibtex main && pdflatex main && pdflatex main

The build is clean: no undefined references or citations, and no overfull or
underfull boxes. Files needed in this folder: `main.tex`, `refs.bib`, `sn-jnl.cls`,
`sn-mathphys-num.bst`, `fig_architecture.pdf`, `fig_memory.pdf`, `fig_accuracy.pdf`
and `fig_scaling.pdf`. The streaming-window figure and Algorithm 1 are drawn in
LaTeX. `cover_letter.tex` is a separate one-page document.

`sn-jnl.cls` and `sn-mathphys-num.bst` are the Springer Nature template files,
converted to Unix line endings. The preamble of `main.tex` redefines the class's
empty running head as `\@empty`, which removes a class-generated "Underfull \vbox"
warning on every page without changing the output.

## Before submission

Resolve every red `\MISSING{}` marker in `main.tex` and `cover_letter.tex`:
co-authors, affiliation, author contributions, funding, competing interests,
the archived-release DOI and the FTNCT'09 prior-publication paragraph.

## Where the numbers come from

Every number is generated from files under `research/results/raw/`. The cluster and
two-stage bootstrap intervals (Table 6) come from
`2026-11-11_{secrets,presidio_research,redactionbench}_test_cluster_bootstrap.json`,
produced by `benchmarks/cluster_bootstrap.py` from the per-document predictions in
`2026-11-11_checkpoints/`.
