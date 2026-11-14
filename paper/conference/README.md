# Conference paper

*The Agent Holds the Key: Auditing What LLM Agents Learn Through Redaction Tools*: a differential egress audit of the tool's content-free replies (and
the fix), the regex-gated neural name tier, and the per-call cost of the guardrail.
Pre-registered in `PROTOCOL.md`, with its departures. See `../README.md` for the
layout, the build and how to move it to a venue.

| File | What it is |
|---|---|
| `PROTOCOL.md` | Research questions, hypotheses, systems, corpora, metrics and decision rules, committed before scoring; departures appended |
| `content/` | The text, `01-introduction.tex` … `08-conclusion.tex`; `tab_*.tex` are generated |
| `make_figures.py` | Builds every table (`content/tab_*.tex`) and figure from `research/results/raw/conf/` |
| `wrappers/` | `generic`, `ieeetran-conf`, `springer-llncs`, `acm-sigconf` |
| `MODEL_SHA256.txt` | Hashes of the neural model files and the checkpoint revision |
| `cover_letter.tex` | Venue-neutral cover letter; set `\Venue` and `\Chairs` |
| `SUBMISSION.md` | What to upload and what the authors must confirm |

## Reproduce

Every experiment's command is in `PROTOCOL.md` and the paper's appendix. Raw results
are in `research/results/raw/conf/`; each records the commit it ran on. Then:

    python paper/conference/make_figures.py
    paper/make_submission.sh conference
