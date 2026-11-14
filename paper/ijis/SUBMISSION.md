# Submitting to IJIS

Journal: *International Journal of Information Security* (Springer), via Springer's
Editorial Manager. Article type: original research article.

## Upload

Run `./make_submission.sh`. It builds and checks everything and writes
`submission/` (ignored by git) with:

| Upload as | File |
|---|---|
| Manuscript (PDF) | `main.pdf` |
| LaTeX source | `source.zip`: `main.tex`, `main.bbl`, `refs.bib`, `sn-jnl.cls`, `sn-mathphys-num.bst`, `fig_architecture.pdf`, `fig_memory.pdf` |
| Electronic supplementary material, "Online Resource 1" | `supplementary.pdf` |
| Cover letter | `cover_letter.pdf` |

The manuscript cites Online Resource 1 by that name; upload it with that title.

## Ready in the files

- Title, abstract (237 words), keywords, numbered sections, numbered references.
- Declarations section: funding, competing interests, ethics, consent, data and code
  availability, author contributions, use of generative AI.
- Every result traceable to `research/results/raw/`; real-data evaluations
  pre-registered (protocols and frozen manifests committed before scoring).
- One-page cover letter stating that the manuscript is not under consideration
  elsewhere.

## The authors must confirm before submitting

These are facts only the authors can check; nothing in the files is a placeholder.

1. Names, order, e-mail addresses and the affiliation of all four authors; ORCID iDs
   if you want them shown (Editorial Manager asks for them).
2. Every co-author has read and approved the final manuscript (the Declarations say
   so) and agrees to the author-contribution statement.
3. The funding statement (Article Processing Charges supported by Amrita Vishwa
   Vidyapeetham) is accurate for this journal's publishing model.
4. The generative-AI statement matches how the tool was used.
5. No version of this work is under review elsewhere. The manuscripts in
   `paper/journal`, `paper/ieee-conference` and `paper/ftnct09` are superseded
   and must not be submitted while this one is under review.

## Optional, strengthens the paper

- A second person labels the Loghub templates blind
  (`python -m benchmarks.loghub_agreement sheet`, then `agree`); report the
  agreement in the threats paragraph. The paper currently states that the labels
  were checked by one author and that the tool is released.
