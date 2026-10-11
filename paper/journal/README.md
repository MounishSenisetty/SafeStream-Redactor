# Journal manuscript (Computers & Security, Elsevier `elsarticle`)

## Overleaf

1. New Project → Upload Project, or upload these files to the project root
   (no subfolders):
   - `main.tex`
   - `refs.bib`
   - `fig_architecture.pdf`, `fig_memory.pdf`, `fig_accuracy.pdf`, `fig_scaling.pdf`
2. Menu → Compiler: **pdfLaTeX**. Main document: `main.tex`.
3. Recompile. `elsarticle.cls` and `elsarticle-num.bst` ship with Overleaf's TeX
   Live, so nothing else is needed. The streaming-window figure and Algorithm 1 are
   drawn in LaTeX (TikZ, algpseudocode) and need no image files.

`highlights.txt` is uploaded separately at submission, not compiled.

`cover_letter.tex` is a separate document (pdfLaTeX); `author_biographies.md` holds
the biography templates.

## Placeholders

Red `[MISSING: …]` and `[NEEDS CITATION: …]` markers are things only the authors
can supply, or results not yet produced. Search for `\MISSING` and `\NEEDSCITE`.
`refs.bib` entries marked `TODO-VERIFY` have fields that were not confirmed.

## Regenerating the figures

From the repository root, after the result files exist:

    python paper/journal/make_figures.py

Every number in the text comes from a file under `research/results/raw/` or
`research/results/diagnostics/`.
`fig_architecture.pdf` is built from `fig_architecture.tex` (pdfLaTeX).
