# Per-document predictions for the cluster bootstrap (2026-11-11)

Harness checkpoints (`benchmarks/harness.py --checkpoint-dir`): character offsets and
types of every prediction, per test document, no corpus text.

- `post_3d2c6ac/`: harness and SafeStream at 3d2c6ac (post entropy fix, the "exposed"
  code of the paper), plus Presidio 2.2.355 (spaCy 3.8.13, models 3.8.0), gitleaks
  8.28.0 and TruffleHog 3.90.8 (`--no-verification`). `safestream-python` is the
  pattern pipeline (byte-identical to the Rust core); `abl-full-spacy` is +spaCy.
- `pre_874e105/`: SafeStream at 874e105 (pre-exposure), run by the 3d2c6ac harness.

Every point estimate and every document-level paired interval reproduces the
2026-10-11 results. Re-score with `python -m benchmarks.cluster_bootstrap` (outputs:
`../2026-11-11_*_test_cluster_bootstrap.json`).
