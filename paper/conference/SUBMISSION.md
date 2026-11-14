# Submitting the conference paper

No venue has been chosen. Once one is:

1. Pick the wrapper: `wrappers/ieeetran-conf.tex` (IEEE, two columns),
   `springer-llncs.tex` (Springer LNCS/CCIS), `acm-sigconf.tex` (ACM), or
   `generic.tex`. Or copy the closest one and change its `\documentclass` line.
2. Run `../make_submission.sh conference <wrapper>` and check the page count in its
   summary. The core paper fits 8 IEEE two-column pages including references; the
   appendix ("Reproducing the results") can be dropped with `\def\noappendix{}` in the
   wrapper.
3. For a double-blind venue, upload `build/<wrapper>-anon/main.pdf` and
   `source.zip`, and create the anonymised repository mirror that `meta.tex` links to.
4. In `cover_letter.tex`, set `\Venue` and `\Chairs`.

## Ready in the files

- Every number traces to `research/results/raw/conf/` (`python ../audit_numbers.py
  conference`), and the paper shares no result with the journal paper
  (`python ../check_disjoint.py`).
- The study was pre-registered (`PROTOCOL.md`, committed before any scoring), and its
  departures are listed there and summarised in the paper.

## The authors must confirm or supply before submitting

1. Authors, order, e-mails, affiliation and ORCID iDs (`meta.tex`); these are copied
   from the journal paper. Change them if the author list differs.
2. The red `\MISSING{}` items in `content/declarations.tex` and
   `content/acknowledgements.tex`: funding for this paper, author contributions,
   acknowledgements.
3. The generative-AI statement matches how the tool was used.
4. Every co-author has read and approved the manuscript.
5. The venue allows a companion manuscript under review elsewhere, cited as such.
