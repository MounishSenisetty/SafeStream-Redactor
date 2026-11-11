# Demo & Distribution Plan

Status: **proposal, nothing implemented yet.** Based on the repository at `54beccb`
(v0.5.0) and on checks run against the live PyPI release on 2026-11-10.

## 1. What exploration found

### Works today (verified)

- `python -m build` produces a 199 kB pure-Python wheel and a 176 kB sdist;
  `twine check --strict` passes; `memstream/` is correctly excluded.
- `pip install safestream-redactor==0.5.0` into a clean venv works, and the README's
  first example prints the documented output.
- Release automation is solid: Trusted Publishing, tag/version guard, wheel + sdist
  smoke test, TestPyPI dry run, a 5-target abi3 wheel matrix for the Rust core.
- The core imports nothing platform-specific at import time (only `threading`), and
  `api.dispatch()` and `MCPServer.handle()` are pure functions with no I/O. This matters
  for Phase 3.

### Broken or misleading (each is a work item below)

| # | Finding | Evidence |
|---|---|---|
| F1 | **`pip install 'safestream-redactor[native]'` fails.** `safestream-redactor-native` has never been published. | `pip index versions safestream-redactor-native` → no matching distribution |
| F2 | Native crate is `0.4.0`; the extra requires `>=0.5.0,<0.6`. Even a publish today would not satisfy it. | `native/Cargo.toml`, `pyproject.toml` |
| F3 | `README.md` advertises `[native]` as a working install; `src/README_PYPI.md` says it is not on PyPI. | README "Install" vs PyPI README "Optional extras" |
| F4 | `--backend native` without the extension prints the same fallback warning **five times**, and tells the user to "build it from `native/` with maturin". | clean-venv run |
| F5 | **The PyPI page is stale.** It says "six subcommands" (there are nine: `deanonymize`, `fanotify` missing), shows version `0.4.0`, omits the `crypto` extra, the `hash`/`encrypt`/`fictionalize` modes and the 0.5.0 entity types. Two READMEs drift. | `src/README_PYPI.md` vs `cli.py`, `CHANGELOG.md` |
| F6 | `docs/RELEASING.md` says "Published so far: 0.1.0, 0.2.0, 0.3.0"; PyPI has 0.4.0 and 0.5.0. | `pip index versions` |
| F7 | README defects: an empty code span ("Unicode `` stays on the fast DFA path"), a mangled one-line ONNX command, `scripts/export_onnx.py` referenced in the pip path (not in the wheel), a 693-line length dominated by a research-grade Evaluation section. | `README.md` lines 46, 77, 163, 507–623 |
| F8 | **There is no live website.** The only UI is the Streamlit playground, which is local-only *by construction* (loopback bind, netguard, a banner that warns when hosted). No Pages/Spaces deployment exists. | `ui/launcher.py`, `.github/workflows/` |
| F9 | Only the Linux x86_64 native wheel is ever imported in CI; macOS, Windows and aarch64 wheels are built but never loaded. No musllinux wheel, so `[native]` on Alpine would fall to a source build needing Rust. | `native-wheels.yml` |
| F10 | CI tests an editable install only. The built wheel is smoke-tested on Linux/3.12 alone, and the `ui`/`crypto` extras are never installed from a wheel. | `ci.yml`, `publish.yml` |

## 2. Decisions needed from you

Defaults are what the plan assumes if you say nothing.

1. **Live demo architecture (Phase 3).** Default: **in-browser** (option A in 5.1).
2. **Publishing the native wheel** needs one manual step only you can do: a PyPI
   *pending publisher* for `safestream-redactor-native` (workflow `native-wheels.yml`,
   environment `pypi-native`) and a GitHub Pages source set to "GitHub Actions".
3. **One README.** The brief says `README.md` is also the PyPI page, so the plan deletes
   `src/README_PYPI.md`. Default: delete.
4. **Next version.** Default: `0.5.1` for both distributions (the `[native]` pin
   `>=0.5.0,<0.6` then resolves with no change).
5. **Trove status.** `Development Status :: 3 - Alpha` undersells a 95%-coverage,
   five-release package. Default: move to `4 - Beta`.

---

## 3. Phase 1 — PyPI config & build

Goal: every documented `pip install` line works on Linux, macOS and Windows, on
CPython 3.10–3.14, and CI proves it before each upload.

### 1.1 Make the hybrid Python/Rust install real (F1, F2, F9)

The two-distribution design stays: a pure-Python `safestream-redactor` that installs
everywhere with zero dependencies, plus an optional abi3 `safestream-redactor-native`
accelerator. This is the right shape — nobody ever needs a compiler for the base
install. What is missing is the second half actually shipping.

- Bump `native/Cargo.toml` (and `Cargo.lock`) to the package version.
- **Lockstep guard:** one CI step comparing `__version__` with the Cargo version, so
  F2 cannot recur.
- **Wheel matrix:** add `musllinux_1_2` x86_64 + aarch64. Build Linux aarch64 on the
  native `ubuntu-24.04-arm` runner instead of cross-compiling, so it can be tested.
- **Import-test every wheel on its own platform** (`pip install` the artifact, import
  it, run one `Redactor(backend="native")` redaction) — today four of five are
  published untested.
- **One release, correct order:** make `native-wheels.yml` callable (`workflow_call`)
  and have `publish.yml` run it first, so `safestream-redactor` X.Y.Z is never
  uploaded before `safestream-redactor-native` X.Y.Z exists. Drop the separate
  `native-v*` tag.
- Verify the native sdist builds from a clean checkout with only `maturin` + Rust
  (the fallback for platforms without a wheel).

### 1.2 Runtime behaviour of the fallback (F4)

- Emit the "native not installed" warning **once per process**, from the one shared
  `_attach_native` path all five tiers call, not once per tier.
- Change its text to the real fix: `pip install 'safestream-redactor[native]'`.

### 1.3 Metadata (`pyproject.toml`)

- `readme = "README.md"`; add `/README.md` to the sdist `include`; delete
  `src/README_PYPI.md`. The `Dockerfile` `COPY` line and `docs/RELEASING.md` follow.
- Add a second console script `safestream-redactor = "safestream_redactor.cli:main"`
  so `pipx run safestream-redactor` and `uvx safestream-redactor` work with no
  `--from` flag. `safestream` stays the documented name.
- Classifiers: status (decision 5), `Environment :: Console`,
  `Intended Audience :: Information Technology` / `System Administrators`,
  `Topic :: Security`, `Topic :: System :: Logging`. Keywords: add `gdpr`, `hipaa`,
  `log-sanitization`, `mcp`, `data-loss-prevention`.
- `[project.urls]`: add `Source`, `Demo` (the Phase 3 URL) and `Security`.
- Add an `all` extra (`ui`, `crypto`, `native`) for the "give me everything" install.
  `ner`/`onnx` stay out of it: they pull large downloads.

Not doing: moving `dev`/`bench` to PEP 735 dependency groups (churns every CI line
and doc for no user-visible gain); merging the Rust core into one maturin-built
distribution (it would take away the compiler-free, any-platform base install).

### 1.4 Install matrix in CI (F10)

One new `install` job, run on PRs and before publish. It builds the wheel + sdist
once, then for `{ubuntu, macos, windows} × {3.10, 3.14}`:

- installs the **wheel** (not editable) into a fresh venv and runs
  `safestream --version`, a stdin redaction and `python -c "import safestream_redactor"`;
- installs `[crypto]` and round-trips `encrypt` → `deanonymize`;
- installs `[ui]` and checks `safestream ui --headless` answers its health check;
- on Linux also: installs from the **sdist**, runs `pipx run`, and repeats the base
  smoke test in `python:3.12-alpine` (musl).

### 1.5 Release docs (F6)

Rewrite `docs/RELEASING.md` for the single-tag flow and remove the hand-maintained
"published so far" list (PyPI is the source of truth).

**Phase 1 exit criteria:** on a TestPyPI dry run, `pip install safestream-redactor`,
`…[native]`, `…[ui]`, `…[crypto]` and `…[all]` all succeed on the three OSes;
`--backend native` runs with no warning; the install job is green.

---

## 4. Phase 2 — README & PyPI page copy

Goal: one `README.md`, about 250–300 lines, that renders identically on GitHub and
PyPI and gets a new user to a redacted line of output in under a minute by whichever
route they prefer.

### 2.1 Constraints that make one file work in both places

- Absolute `https://github.com/...` links and `raw.githubusercontent.com` image URLs
  only (relative links break on PyPI).
- No Mermaid (PyPI shows the source). The ASCII pipeline diagram stays; Mermaid
  diagrams remain in `docs/architecture/`.
- Guard: a test that fails on any relative link or ```` ```mermaid ```` fence in
  `README.md`; `twine check --strict` already covers rendering.
- **Every Python block is executed in CI** (`tests/test_readme.py`: extract the
  fenced `python` blocks, run them), and the shell quickstarts are the commands
  `examples/run_demo.sh` already runs. No more F5/F7-style drift.

### 2.2 Structure

```
# SafeStream-Redactor
  badges: CI · PyPI · Python versions · License · Live demo
  One-sentence pitch + the claim, stated once:
    "Redact a 100 GB log in the same memory as a 1 KB one."
  [ Try the live demo ]  [ Docs ]  [ PyPI ]
  Animated capture of the demo (redact + streaming inspector)

## 30-second quickstart
  pip install safestream-redactor
  one piped `safestream redact` command and its real output

## Why SafeStream
  Four short value props, each with its proof link:
  - Constant memory      — 1 GB file under a 16 MB allocation cap (test link)
  - PII *and* secrets    — one pass; what Presidio-style PII engines skip
  - Offline by default   — network guard, optional seccomp/netns, zero runtime deps
  - Deterministic        — sequential, parallel and native output byte-identical
  Compact comparison table vs "load-the-whole-file" tools

## Choose your path
  | I want to…                       | Use            | Jump to |
  | sanitize files or pipes          | CLI            | …       |
  | redact inside my app             | Python library | …       |
  | call it from another language    | REST API       | …       |
  | give an AI agent a redaction tool| MCP server     | …       |
  | try it without installing        | Web demo       | …       |
  | block secrets in CI              | CI gate        | …       |
  | run it isolated                  | Docker         | …       |

## Quickstarts            (each: install line → command → real output → "next" link)
  ### CLI                 redact, detect, mask, a directory with --workers, stdin
  ### Python              redact(), detect(), redact_file(), redact_stream()
  ### REST API            safestream serve + curl /redact and /scan, with responses
  ### MCP server          client JSON config + one scan call and its content-free reply
  ### Web demo            hosted link; `pip install '…[ui]' && safestream ui` for local
  ### CI gate             pre-commit hook, GitHub Action, --sarif
  ### Docker              ghcr.io image, --network none

## Install options
  Table: base · [native] · [ui] · [crypto] · [ner] · [onnx] · [all]
  — what each adds, its size/cost, supported platforms. pipx / uvx one-liners.

## What it detects
  Entity table (PII · labeled IDs · credentials · generic secrets · regional · custom)

## How it works
  ASCII pipeline diagram + the three-sentence rolling-buffer explanation

## Performance and accuracy
  5-line honest summary: throughput range, where it beats Presidio, where it loses.
  Link to the full tables.

## Limitations                (kept, shortened: best-effort on free prose; the 3 recall levers)
## Security model             (short; link to SECURITY.md)
## Documentation              (index of docs/)
## Contributing · License · Citation
```

### 2.3 Content moves

- The Evaluation section (120 lines of tables and caveats) moves verbatim to
  `docs/EVALUATION.md`; the README keeps the summary and a link.
- The Web Interface reference (60 lines) moves to `docs/WEB_UI.md`.
- The full CLI option reference and exit codes from `README_PYPI.md` move to
  `docs/CLI.md`. The README shows only the commands a first-time user needs.
- `docs/DEMO.md` stays as the long guided tour and is linked from "Choose your path".

**Phase 2 exit criteria:** README ≤ 300 lines; README tests green; the TestPyPI
project page renders with working links and images; each quickstart was pasted into
a clean environment and produced the output shown.

---

## 5. Phase 3 — UI/UX demo overhaul

### 5.1 Architecture decision

The product's promise is "your data never leaves your machine". A hosted demo that
asks visitors to paste logs into someone else's server contradicts it, and the
existing Streamlit page would (correctly) show its "not fully local" warning there.

| | A. In-browser (recommended) | B. Hosted Streamlit (HF Spaces / Community Cloud) |
|---|---|---|
| How | Static page on GitHub Pages; the real wheel runs in the visitor's tab via Pyodide (WebAssembly) | Deploy `ui/app.py` to a server |
| Data path | Never leaves the browser — the demo *is* the privacy claim | Pasted text goes to a third-party server |
| Ops | None: no server, no cold starts, no abuse surface, free | Sleeping containers, rate limits, a public upload endpoint to police |
| Engine fidelity | Same wheel as PyPI; pure-Python backend only | Same engine; could add native |
| Cost to build | New static front end (~1 HTML file + a worker) | Small; but must weaken local-only guards |

Option A is feasible because the base wheel is pure Python with no dependencies and
imports nothing WASM-hostile. **First task of the phase is a half-day spike** that
loads the built wheel in Pyodide and runs `Redactor().redact()`, `api.dispatch()`,
`MCPServer().handle()` and `ui.core.trace_chunks()`. If it fails on something not
cheaply fixable, fall back to B with an explicit "demo server — do not paste real
secrets" banner.

The local Streamlit playground (`safestream ui`) stays as the full-power local tool
(large files, parallel engine). It gets no rewrite.

### 5.2 What the demo contains

No new detection or protocol logic: every panel calls code that already ships.

| Panel | Shows | Backed by (existing) |
|---|---|---|
| **Playground** | Paste or drop text → highlighted findings by severity, side-by-side redacted output, mode switch (replace / mask / hash), type filters, confidence slider, copy + download | `ui.core.scan`, `highlight_html`, `redact_text` |
| **Streaming inspector** | The rolling buffer, pass by pass: context / emitted / carried bands, boundary retreats, play / step / seek. A live "buffer size vs. input size" readout makes the constant-memory claim visible | `ui.core.trace_chunks`, `pass_html` |
| **REST API console** | Request editor for `GET /health`, `/detectors`, `POST /redact`, `/scan`; real status + JSON response; "copy as curl" against `safestream serve` | `api.dispatch()` (pure function) |
| **MCP console** | `initialize` → `tools/list` → `tools/call`; raw JSON-RPC in and out; shows that `scan` returns metadata, never the secret; copyable client config | `MCPServer.handle()` (transport-pure) |
| **Get it** | Install commands and a "copy as Python / CLI" snippet reflecting the current settings | static |

### 5.3 Design requirements ("enterprise-ready")

- **Layout:** top bar (product, version, GitHub, PyPI), left settings rail, main
  work area with tabs. Rail collapses to a sheet below 900 px; fully usable at
  360 px; no horizontal page scroll (wide code and tables scroll inside themselves).
- **Visual language:** restrained and dense rather than marketing-styled. One accent
  colour, a neutral scale, system UI font + a monospace for data, light and dark
  themes following the OS with a manual toggle. Severity is never colour-only
  (icon + label too).
- **Trust signals up front:** a persistent "Runs entirely in your browser — nothing
  is uploaded" indicator, backed by a `Content-Security-Policy` whose `connect-src`
  allows only the page's own origin (the Pyodide runtime is vendored into the Pages
  build, not hot-linked), so the claim is checkable in DevTools.
- **Responsiveness:** engine runs in a Web Worker so the page never freezes; a
  staged progress indicator covers the one-time runtime load; results re-render on
  debounced input; the runtime is cached for repeat visits.
- **Honest limits:** input capped (about 1 MB) with a pointer to the CLI for real
  files; a "pure-Python backend in the browser; install `[native]` locally for
  3–12×" note.
- **Accessibility:** WCAG 2.1 AA contrast, full keyboard operation, visible focus,
  ARIA tabs, `prefers-reduced-motion` respected in the inspector.
- **First-run experience:** opens with a sample log already redacted — a visitor
  sees the value before typing anything. Three samples: application log, `.env`
  file, support-ticket prose.

### 5.4 Implementation shape

- `site/index.html`, `site/worker.js`, `site/style.css`. No framework, no bundler,
  no `node_modules`: the page is a few panels over a worker.
- `.github/workflows/pages.yml`: build the wheel from the tagged commit, copy it and
  a pinned Pyodide into the site, deploy to GitHub Pages. The demo always runs the
  released version and displays it.
- One Playwright smoke test in CI: page loads, the sample redacts, the REST and MCP
  consoles return the expected JSON, and **no request leaves the page's origin**.
- Streamlit playground: only the fixes that fall out of the above (shared sample
  texts, updated screenshots). Regenerate `docs/images/` and the README capture from
  the new demo.

**Phase 3 exit criteria:** public URL live and linked from the README badge and
`[project.urls]`; Lighthouse accessibility ≥ 95; usable on a phone; smoke test green;
cold load to first redaction under ~8 s on broadband, instant when cached.

---

## 6. Sequencing and risk

| Phase | Depends on | Main risk | Mitigation |
|---|---|---|---|
| 1 PyPI & build | Decision 2 (pending publisher) | A wheel for an untested platform is broken | Per-platform import test; TestPyPI dry run first |
| 2 README | Phase 1 (commands must be true); demo URL can be a placeholder until Phase 3 | Copy drifts again | README blocks executed in CI |
| 3 Demo | Phase 1 wheel | Pyodide incompatibility | Spike first; option B as fallback |

Phases 1 and 2 ship together as release `0.5.1`. Phase 3 ships independently (a
static site needs no package release) and only adds a URL to the README.

Out of scope, noted for a public launch: `REDUNDANT_FILES_AUDIT.md`,
`Code-Review Diaries - G2/` and `docs/VIVA_QA.md` are coursework artifacts sitting in
a repository about to be shown to adopters; consider moving them out of the default
branch.
