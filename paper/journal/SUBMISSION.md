# Submitting the journal paper

No venue has been chosen. Once one is:

1. Pick the wrapper (`wrappers/springer-sn-jnl.tex`, `elsevier-elsarticle.tex`,
   `ieee-journal.tex`, `acm-journal.tex`, or `generic.tex` for a journal without a class),
   or copy the closest one and change its `\documentclass` line.
2. Run `../make_submission.sh journal <wrapper>`. Upload
   `build/<wrapper>/main.pdf` (or `build/<wrapper>-anon/` for a double-blind venue),
   `build/<wrapper>/source.zip`, `build/supplement/supplementary.pdf` as the electronic
   supplementary material ("Online Resource 1"), and `cover_letter.pdf`.
3. Check the page count in the build summary against the venue's limit. The generic
   build is 29 pages including references and the proofs appendix.
4. In `cover_letter.tex`, set `\Venue` and `\Editor`.

## Ready in the files

- Title, abstract, keywords, numbered sections and references, declarations (funding,
  competing interests, ethics, consent, data and code availability, author
  contributions, use of generative AI).
- Every result traceable to `research/results/raw/`; the real-data evaluations were
  pre-registered (protocols and frozen manifests committed before scoring).
- The companion conference paper is cited as under review (as "Anonymous" in the blind
  build), and the cover letter names it and offers it to the editor. The two papers
  share no result: `python ../check_disjoint.py`.

## The authors must confirm before submitting

Only the authors can check these facts.

1. Names, order, e-mail addresses and affiliation of all four authors (`meta.tex`);
   ORCID iDs if the venue shows them (the fourth argument of each `\ssAuthor`).
2. Every co-author has read and approved the final manuscript and agrees to the
   author-contribution statement.
3. The funding statement (Article Processing Charges supported by Amrita Vishwa
   Vidyapeetham) holds for the chosen venue's publishing model.
4. The generative-AI statement matches how the tool was used.
5. No version of this work is under review elsewhere. The drafts in `../archive/` must
   not be submitted.
6. For a double-blind venue: create the anonymised mirror that `meta.tex` links to, and
   check the venue's rules on citing your own work under review.

## Optional, strengthens the paper

- A second person labels the Loghub templates blind
  (`python -m benchmarks.loghub_agreement sheet`, then `agree`); report the agreement
  in the threats paragraph. The paper states that the labels were checked by one
  author and that the tool is released.
