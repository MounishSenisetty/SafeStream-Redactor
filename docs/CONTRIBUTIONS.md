# Statement of Contribution

> **This page must stay true.** An examiner can run `git log --author=… -- <path>` on
> every row below. Each member completes and signs *their own* section; list only
> work you personally wrote, reviewed-and-changed, or can derive from first
> principles at the viva. Evidence columns cite commits or PRs, not intentions.
>
> Record at the time of writing (`git shortlog -sn`, 2026-10-02): the implementation
> history is attributed almost entirely to Member 1. Members 2 and 3 each have one
> README edit. The rows for Members 2 and 3 are therefore **templates plus a hand-off
> plan** (§3), not claims. Fill them in only as the work is actually done and merged
> under your own authorship.

## 1. Ownership domains

| # | Domain | Modules / artefacts |
|---|---|---|
| **D1** | **Core engine and systems** | `engine.py` (sliding window, emit-boundary retreat, fail-closed overlap), `parallel.py` (seam protocol), `docs/FORMAL_MODEL.md` (Theorems 1–3), `native/` (Rust core, Unicode parity), `memory_budget.py` + `RLIMIT_AS`, `watch.py` + `docs/FANOTIFY.md`, `netguard*.py` |
| **D2** | **Evaluation, benchmarking, security audit** | `benchmarks/` (`redactionbench/`, `presidio_compare.py`, `generate_*dataset.py`), `tests/test_equivalence_fuzz.py`, `docs/AUDIT_FINDINGS.md`, `research/`, `paper/` evaluation sections |
| **D3** | **Platform, interfaces, integration** | `api.py` + `docs/rest-api.md`, `mcp_server.py`, `ui/` (Streamlit), `.github/workflows/`, `Dockerfile`, packaging (`pyproject.toml`, wheels), `detectors/onnx_ner.py` |

## 2. Record as of 2026-10-02

| Member | Commits attributed by git | What the record shows |
|---|---|---|
| Mounish Senisetty (Member 1) | ~150 | All of D1, and — as authored — the first versions of D2 and D3 as well (`git log -- benchmarks/redactionbench` 11 commits, `.github/workflows` 16, `ui/` 6, `mcp_server.py` 1, `onnx_ner.py` 1, `docs/AUDIT_FINDINGS.md` 4, `native/src` 6, `engine.py` 7). |
| Sandhiya Kennedy | 1 | README bibliography formatting (`336fb50`). |
| Rashrith7 | 1 | README wording (`d2bf373`). |

Bots (`dependabot`, `copilot-swe-agent`) account for the remainder; the equivalence
fuzzer, the fail-closed overlap change and the like-for-like benchmark rows were
added in this review cycle and are not yet attributed to any member's *understanding* —
see §3.

## 3. Hand-off plan: make D2 and D3 genuinely owned

Owning a domain means you have run it, changed it, and can defend it. Each task has an
acceptance test and produces a commit under your own name. Do not mark a row complete
until the PR is merged.

### Member 2 — D2 (evaluation, benchmarking, audit)

| Task | Acceptance | Done when |
|---|---|---|
| Run the equivalence fuzzer on your machine at the `deep` profile (`HYPOTHESIS_PROFILE=deep SAFESTREAM_FUZZ_EXAMPLES=3000 pytest tests/test_equivalence_fuzz.py`) and report the result with your environment | A results note under `research/results/` | PR merged |
| Add one new mutant to the fuzzer's mutation check (e.g. drop the contextual prefix) and show it is killed | New test in `tests/test_equivalence_fuzz.py` that fails on the mutant | PR merged |
| Reproduce `benchmarks/presidio_compare.py` on your hardware; compare to `benchmarks/PRESIDIO_COMPARISON.md` | Delta table with explanation of any >20 % difference | PR merged |
| Write the *Threats to validity* section of the report (synthetic corpus, one dataset, one machine, NER model choice) | Section in `paper/` or report | Reviewed by Member 1 |

### Member 3 — D3 (platform, interfaces, integration)

| Task | Acceptance | Done when |
|---|---|---|
| Write a threat model for `mcp_server.py` and the REST API: what leaves the process, what is logged, what an agent can exfiltrate | `docs/THREAT_MODEL_INTERFACES.md`, with one test per claim | PR merged |
| Wire `WindowConfigurationError` into the REST API and UI error paths (HTTP 422 / friendly message) with tests | Tests in `tests/test_api.py`, `tests/test_ui_app.py` | PR merged |
| Add an ONNX-tier case to the equivalence fuzzer using the existing mock model (`tests/test_onnx_mock_pipeline.py`) | A passing property, plus a note on why its window assumption (A2) holds | PR merged |
| Own the release path: cut a test tag, confirm wheels, SBOM and provenance in the workflow output | Link to a successful workflow run | Run linked |

## 4. Wording for the report and slides (fill in the brackets truthfully)

> **Statement of contribution.** The system architecture, the streaming and parallel
> engines, the formal model, the Rust core, and the kernel-level controls were designed
> and implemented by **[Member 1]**. **[Member 2]** contributed **[exactly what, with
> commit/PR links]**. **[Member 3]** contributed **[exactly what, with commit/PR links]**.
> Repository history is the authoritative record: `git shortlog -sn` and
> `git log --author=<name>`.

A panel that sees a statement matching the history will probe your understanding;
a panel that sees one contradicting it will probe your integrity. The first is
survivable.
