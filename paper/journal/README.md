# Journal paper

*Bounded-memory streaming redaction of personal data and credentials with a
whole-document equivalence guarantee*: the streaming engine's equivalence theorems,
its memory and throughput, and the detection evaluation of the pattern tiers
(RQ1–RQ7). Written once and kept separate from any template; see `../README.md` for
the layout, the build and how to move it to a venue.

| File | What it is |
|---|---|
| `content/` | The text: `01-introduction.tex` … `09-conclusion.tex`, `abstract.tex`, `keywords.tex`, `declarations.tex`, `acknowledgements.tex`, `appendix.tex` (proofs), `preamble.tex` |
| `meta.tex` | Title, authors, affiliation, repository link |
| `wrappers/` | `generic` (plain article), `springer-sn-jnl`, `elsevier-elsarticle`, `ieee-journal`, `acm-journal`; the Springer class files are here |
| `supplement/supplementary.tex` | Online Resource 1 (supplementary tables and figures), a plain article |
| `figures/` | Figures; `make_figures.py` rebuilds the plotted ones from the raw results |
| `cover_letter.tex` | Venue-neutral cover letter; set `\Venue` and `\Editor` |
| `SUBMISSION.md` | What to upload and what the authors must confirm |

## Build

    ../make_submission.sh journal          # every wrapper, normal and anonymous, plus the supplement
    ../make_submission.sh journal generic  # one wrapper

The generic, Springer and ACM builds are free of overfull boxes. The Elsevier
(preprint, 12 pt) and two-column IEEE builds set some wide tables past the margin.
Adjust those tables if one of these classes is chosen.

The restructuring out of the single-file IJIS manuscript changed no number:
`python ../check_disjoint.py --same <old main.tex> content` reports the same 766 numbers
before and after.

## Where the numbers come from

Every number is computed from files under `research/results/raw/` in the repository
root, produced by the harness and scripts in `benchmarks/`. The real-data
evaluations follow protocols committed before any system was run on them:
`benchmarks/TAB_PROSE_PROTOCOL.md` (TAB development, held-out training split and
Wikipedia biographies), `benchmarks/CREDDATA_PROTOCOL.md` (CredData), and the
Loghub label files `benchmarks/corpora/loghub_slots*.json` (verified before scoring).
