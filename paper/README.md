# Manuscripts

Two papers, written once and kept separate from any publisher template so that either
can go to any venue. They ask different questions on different data and share no
result (`check_disjoint.py` enforces this).

| Folder | Paper | Question |
|---|---|---|
| `journal/` | *Chunking Without Leaking: Provably Equivalent, Bounded-Memory Redaction of Personal Data and Credentials* | Is chunked redaction provably correct and bounded in memory, and how well do the pattern tiers detect on held-out and real data? |
| `conference/` | *The Agent Holds the Key: Auditing What LLM Agents Learn Through Redaction Tools* | What does an LLM agent learn through the tool: egress through content-free replies, the gated neural tier, and the cost per tool call? |
| `archive/` | Earlier drafts (Elsevier, IEEE conference, FTNCT'09) | Superseded. Never submit them. |

## Layout (both papers)

```
content/      the text: one .tex per section, abstract, keywords, declarations, appendix
meta.tex      title, authors, affiliation, repository link (entered once)
refs.bib      bibliography
figures/      figures, built by make_figures.py from research/results/raw/
wrappers/     one thin main file per document class; no text of its own
```

## Build

```bash
paper/make_submission.sh journal
```

```bash
paper/make_submission.sh conference
```

Each wrapper is built twice, normally and anonymised (`\def\anonymousbuild{}`). The
anonymised build hides authors, acknowledgements, funding and author contributions,
cites the companion paper as "Anonymous", and swaps the repository link for an
anonymised mirror. Results go to `<paper>/build/<wrapper>[-anon]/`: `main.pdf`, the log,
and `source.zip`, which builds on its own. The script fails on a LaTeX error or an
undefined reference or citation, and counts overfull boxes.

```bash
python paper/check_disjoint.py
```

## Moving a paper to a venue

1. Pick the wrapper for the venue's class, or copy the closest one and change the
   `\documentclass` line.
2. If the venue is double-blind, submit the `-anon` build and set up the mirror that
   `meta.tex` links to (for example anonymous.4open.science).
3. Check the page count in the build summary against the venue's limit. The conference
   appendix can be dropped with `\def\noappendix{}`.
4. Fill in the venue name in `cover_letter.tex`.
5. Upload `build/<wrapper>[-anon]/main.pdf` and `source.zip`.
