# Collection plan: a public, real-world corpus for the IJIS evaluation

**Status:** draft for decision. Nothing has been collected. The decisions in
Section 9 must be made, and ethics clearance obtained where required, before
any log is downloaded.

## 1. Goal and what reviewers need

The paper's main weakness is that all three test corpora are synthetic,
rule-author examples, or contaminated. This corpus answers it with authorised,
real CI and application logs, double-annotated by humans, scored once with
frozen code by the pipeline in this folder (`README.md`).

The design follows from four things a reviewer will check:

1. **Real artefacts** with clear provenance and permission to use them.
2. **Unbiased selection.** Documents are chosen by a rule fixed in advance,
   never by running any evaluated tool and keeping what it flags.
3. **Independent gold.** Two humans annotate without seeing any system's
   output; agreement is reported; disagreements are adjudicated.
4. **Enough independent units.** RedactionBench's 11 domains made its cluster
   intervals imprecise, so the target here is **at least 20 sources** (projects).

## 2. Constraints found while drafting

- **GitHub Acceptable Use Policies.** Researchers may use *public,
  non-personal* information from GitHub for research, and only if resulting
  publications are open access. CI logs routinely contain personal data
  (committer names and e-mail addresses), so bulk scraping does not fit that
  permission. This plan therefore collects only with **maintainer opt-in**
  (Section 3) and requires the article to be **open access** (Decision D2).
  Re-read the current policy text before starting; it is the authority, not
  this summary.
- **Retention.** GitHub Actions logs on public repositories are kept for at
  most 90 days. Logs are snapshotted once at collection and cannot be
  re-downloaded later, so reproducibility rests on the frozen manifest
  (run IDs and SHA-256 hashes), not on re-collection.
- **Personal data.** Logs contain personal data, and processing it may fall
  under GDPR or similar law depending on where the authors and subjects are.
  Ethics review and a lawful basis (typically research or public interest, with
  data minimisation) are needed (D1).

## 3. Sources

**Primary: public open-source projects whose maintainers opt in.**

1. **Sampling frame.** Public GitHub repositories with an OSI-approved licence,
   at least 50 stars, GitHub Actions runs in the last 60 days, and at least one
   deploy, release, integration-test or end-to-end workflow. These jobs touch
   credentials and services, unlike plain unit-test jobs. The frame is built
   with the public search API from repository metadata only, without opening
   any log.
2. **Random draw.** Shuffle the frame with a fixed seed, recorded in this file
   before drawing, and invite maintainers in that order until about 25 projects
   have agreed (D3).
3. **Invitation.** Send a short, plain request: the purpose, what is collected,
   that nothing is published except annotations, hashes and aggregates, that
   live secrets will be reported privately, and that they can withdraw. Keep a
   record of each consent with the maintainer's handle and the date. That record
   is the `authorisation` in `provenance.json`.

**Optional second stratum: the authors' own or a partner organisation's logs**,
under a written data-use agreement. It adds realism (application logs, not only
CI), but report it as a separate stratum, because the source population differs.

**Excluded:** forks, archived repositories, repositories with fewer than two
contributors, and anything the authors maintain or contribute to. The last
exclusion avoids author bias.

## 4. Selecting documents within a project

For each consenting project, using only metadata:

1. List workflow runs from the last 60 days, and stratify by workflow kind
   (deploy/release, integration/e2e, other) and by conclusion (success, failure).
   Failures are kept on purpose: failing jobs dump environments and connection
   strings more often.
2. Draw **4 runs per project** with the fixed seed: up to 2 deploy/release, 1
   integration/e2e and 1 other, filling from the next stratum if one is empty.
3. **Document unit.** One step's log is one document. If it is longer than
   20,000 characters, take the 20,000-character window that ends at the step's
   last line. That is a deterministic rule that keeps the error output, which is
   usually at the end, and keeps annotation time bounded. Record the offset.

Target: **25 projects × 4 documents = 100 documents**, plus **10 pilot
documents** from 3 further projects for annotator training. Pilot documents are
never scored.

**No tool-based enrichment.** Do not keep only logs that any scanner, regex or
model flags as containing secrets. That would select for what the evaluated
systems can find and inflate their recall. The stratification by workflow kind
is the only enrichment, and it is decided before any log is opened.

## 5. Handling the data

- **Download** through the authenticated REST API with a read-only token, at
  most once per run, and keep the raw zip only until the document is extracted.
- **Storage:** an encrypted volume (for example LUKS or an encrypted APFS
  disk image), readable only by the two annotators and the adjudicator. Never
  in a cloud-synced folder, the repository or an issue tracker.
- **Live secrets:** never test a credential against a live service, and run
  every tool without verification (the harness already passes
  `--no-verification` to TruffleHog). If a value looks live, tell the
  maintainer privately, through GitHub private vulnerability reporting or the
  project's `SECURITY.md` contact, within 7 days, and log the notice. Do not
  wait for the study to end.
- **Minimisation:** keep only the selected step windows. Delete raw downloads
  after extraction. Delete the corpus text after acceptance plus a retention
  period set by the ethics approval. Keep annotations and hashes.
- **Publication:** document IDs are opaque (`ci-0001`), and the mapping from ID
  to repository and run stays private. The paper reports aggregates, and the
  repository holds the frozen manifest (IDs and SHA-256), never text or values.

## 6. Annotation

- **Annotators:** two people with security background, neither involved in
  SafeStream's rule development, plus an adjudicator (one of the authors is
  acceptable). Record each person's role.
- **Guidelines:** `ANNOTATION_GUIDELINES.md`. Train on the 10 pilot documents,
  discuss disagreements, and update the guidelines. Then **freeze the
  guidelines** before the main 100 documents.
- **Independence:** annotators label from the raw text only. They see no
  system's output, no pre-labels and each other's work only after both finish.
- **Pre-labelling:** not used for the gold standard. It may be used once,
  *after* independent annotation and adjudication, as a disclosed "missed-value
  check": an assistant flags candidate values, and the adjudicator decides on
  each. Report how many gold spans that check added. If it uses any evaluated
  system, report that too, because it favours that system.
- **Quality bar:** report binary character-level kappa and span F1. A binary
  kappa below 0.6 means the guidelines are not working; revise them on the pilot
  set before continuing.
- **Effort estimate:** about 15 minutes per document per annotator for
  20,000-character windows. That is roughly 25 hours each for the main set,
  4 hours each for the pilot, and about 10 hours of adjudication.

## 7. Analysis plan (fixed before scoring)

- Code frozen at a tagged commit before the corpus is frozen. No detector,
  threshold or rule changes after any annotation has been seen.
- Systems: the same seven as the paper, with the scanner sensitivity variants.
- **Planned comparisons:** SafeStream pattern versus gitleaks and versus
  TruffleHog, in fully redacted rate and character F1, and SafeStream +spaCy
  versus Presidio sm and lg in character F1. Use the two-stage bootstrap with
  projects as clusters. Report each comparison whatever its sign.
- **Secondary, descriptive:** per-type coverage, credential leak counts and
  no-leak document rate.
- Report the stratum results (public versus organisational) separately if the
  second stratum is used.

## 8. Timeline

| Week | Work |
|---|---|
| 0 | Decisions (Section 9); ethics submission; code tag |
| 1–2 | Sampling frame; invitations; consent records |
| 2–3 | Download, extraction, `provenance.json`; validate |
| 3 | Pilot annotation and guideline revision |
| 4–6 | Main annotation (both annotators, independently) |
| 6 | Agreement report; adjudication; freeze the manifest |
| 7 | Harness runs; scoring; results section and tables |

The ethics review duration dominates and varies by institution.

## 9. Decisions needed before collection

| # | Decision | Recommended default |
|---|---|---|
| D1 | Ethics review and lawful basis for personal data in logs | Submit to the institution's ethics board, describing minimisation, encryption, private disclosure and deletion |
| D2 | Open-access publication (a condition of GitHub's research permission) | Choose the journal's open-access option, or confirm with the editor that the accepted manuscript can be posted openly |
| D3 | Number of projects and documents | 25 projects × 4 = 100 documents, plus 10 pilot documents |
| D4 | Second stratum from own or partner organisation | Include if a data-use agreement can be signed within the timeline; otherwise public only |
| D5 | Annotators and adjudicator | Two external annotators with security background; adjudicator from the author team |
| D6 | Live-secret disclosure contact | One named author, reachable within 7 days |
| D7 | Retention period of the corpus text | Delete text 12 months after publication; keep annotations and hashes |

## 10. Tooling still to build (after decisions)

- `sample.py`: builds the sampling frame and draws projects and runs with a
  fixed seed, from metadata only. It writes `selection.json` (repository, run
  and step IDs) to the encrypted corpus folder, not the repository.
- `fetch.py`: downloads the selected logs once, extracts the step windows and
  writes `documents.jsonl` with SHA-256 hashes. It deletes the raw zips.
- A consent tracker: a CSV of project, maintainer handle, date and scope, in
  the encrypted folder.

The scoring pipeline in this folder already handles everything after
annotation.
