# IJIS submission (International Journal of Information Security, Springer)

This folder is **the** manuscript of the SafeStream-Redactor work. The other folders
under `paper/` are superseded earlier versions and must not be submitted alongside it
(see `../README.md`).

| File | What it is |
|---|---|
| `main.tex` | The manuscript (Springer Nature `sn-jnl`, numbered references, `sn-mathphys-num.bst`) |
| `supplementary.tex` | Online Resource 1 (electronic supplementary material) |
| `cover_letter.tex` | One-page cover letter to the Editor-in-Chief |
| `refs.bib` | Bibliography for `main.tex` |
| `fig_architecture.pdf`, `fig_memory.pdf` | Figures of the manuscript (the streaming-window figure and Algorithm 1 are drawn in LaTeX) |
| `fig_accuracy.pdf`, `fig_scaling.pdf` | Figures of Online Resource 1 |
| `sn-jnl.cls`, `sn-mathphys-num.bst` | Springer Nature template files (Unix line endings) |
| `make_submission.sh` | Builds all three PDFs, checks the logs and writes the upload package |
| `SUBMISSION.md` | What to upload and what the authors must confirm before submitting |

## Build

    ./make_submission.sh            # builds, checks and packages
    pdflatex main && bibtex main && pdflatex main && pdflatex main   # manual build

The builds are clean: no undefined references or citations and no overfull or
underfull boxes. The preamble of `main.tex` redefines the class's empty running head
as `\@empty`, which removes a class-generated "Underfull \vbox" warning on every page
without changing the output.

## Where the numbers come from

Every number is computed from files under `research/results/raw/` in the repository
root, produced by the harness and scripts in `benchmarks/`. The real-data
evaluations follow protocols committed before any system was run on them:
`benchmarks/TAB_PROSE_PROTOCOL.md` (TAB development, held-out training split and
Wikipedia biographies), `benchmarks/CREDDATA_PROTOCOL.md` (CredData), and the
Loghub label files `benchmarks/corpora/loghub_slots*.json` (verified before scoring).
