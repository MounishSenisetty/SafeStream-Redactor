# CredData evaluation protocol

Fixed and committed before any system was run on CredData. Nothing below is
changed after scoring.

## Data

[CredData](https://github.com/Samsung/CredData) (Samsung, MIT licence for the
metadata; each file under its own project's licence): lines of real files from
open-source repositories, labelled by people as holding a credential (`T`), not
holding one (`F`) or holding a test value, example or placeholder (`X`). Its
builder (`download_data.py`) fetches the pinned commits and replaces every real
credential value with a random value of the same shape, so no live secret is
read or stored.

Loader `benchmarks/corpora.load_creddata`: one document per labelled line range
(`LineStart`..`LineEnd`) of a file. A range with at least one `T` row carries
each `T` row's value span as gold; a range whose rows are all `F` or `X` is
gold-free, so any detection on it is a false alarm. The corpus is test-only
(`benchmarks/corpora/splits/creddata.json`, source SHA-256 frozen): no rule,
threshold or configuration is developed or chosen on it.

## Systems

- SafeStream pattern tiers at the evaluated commit of the paper (`3d2c6ac`);
- SafeStream default profile at the current code (`9c10975`, default profile
  unchanged by the prose work);
- gitleaks 8.28.0 and TruffleHog 3.90.8 with default rules and default
  false-positive filtering, TruffleHog without verification.

## Metrics

As in the paper: fully redacted rate over gold values (FR), character precision,
recall and F1, and the false-alarm document rate on gold-free ranges (FA).
Category breakdown of FR is descriptive.

## Statistics

95% percentile bootstrap, 2,000 resamples, seed 0, one shared resample matrix,
under document resampling and two-stage resampling by repository
(`benchmarks/cluster_bootstrap.py`). A difference is robust when significant
under both.

## Planned comparisons

SafeStream pattern (evaluated commit) minus gitleaks and minus TruffleHog, on FR,
character F1 and FA. Everything else is descriptive.

## Known biases, stated in advance

- Only candidate lines are labelled: CredData's authors labelled what their tools
  proposed, so recall is relative to that candidate set, and tools that took part
  in proposing candidates may be favoured.
- Values are obfuscated with shape-preserving random strings; detectors that
  check a checksum or a vendor-specific structure beyond the shape may miss them.
- Each document is the labelled line range only; detectors that use the file
  name or wider context see less than they would in a repository scan.

Results are reported whatever their direction.

## Correction (after scoring, disclosed)

The first loader treated 1,091 line ranges as gold-free although their only rows
were credential (`T`) rows without a value position. The protocol above counts a
range as gold-free only when all its rows are `F` or `X`, so these ranges are
neither gold nor gold-free; the loader now leaves them out (they are listed in the
corpus's `skipped` notes) and the manifest was re-frozen. Gold is unchanged
(14,626 values in 14,189 ranges); the gold-free set shrinks from 50,608 to 49,517
ranges. Every system flagged almost all of the dropped ranges (they hold
credentials), so the correction lowers every system's false-alarm rate. Results
are recomputed from the same per-document predictions, filtered to the corrected
document set; no detector was re-run or changed.

Also reported, descriptively: false alarms split by CredData's label (`F`, not a
credential; `X`, a test value, example or placeholder), and SafeStream's fully
redacted rate across confidence thresholds compared at matched false-alarm rates.
