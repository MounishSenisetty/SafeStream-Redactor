# Stage the RedactionBench dataset here

This directory is where the RedactionBench evaluation harness reads the dataset
from when run **without** `--download` (the default, for network-restricted
environments). It ships empty on purpose — the dataset carries its own license
and is not vendored into this repository.

## What to put here

Any mix of the dataset's exported files:

- `*.parquet` (the native Hugging Face export — recommended), or
- `*.jsonl` / `*.json` / `*.csv`

plus a one-line `REVISION` file recording the dataset commit sha, so runs stay
reproducible.

## How to produce them (on a machine with `huggingface.co` access)

```bash
pip install huggingface_hub
huggingface-cli download RedactionBench/RedactionBench --repo-type dataset \
    --local-dir rb_export

# copy the data files in and pin the revision:
cp rb_export/*.parquet benchmarks/data/redactionbench/     # or *.jsonl / *.json / *.csv
huggingface-cli download RedactionBench/RedactionBench --repo-type dataset \
    --revision main --quiet >/dev/null   # (any method to learn the sha)
echo "<commit-sha>" > benchmarks/data/redactionbench/REVISION
```

(Equivalently, in Python: `datasets.load_dataset("RedactionBench/RedactionBench")`
then `.to_parquet(...)` / `.to_json(...)` per split.)

## Then

```bash
python -m benchmarks.redactionbench.run inspect --data-dir benchmarks/data/redactionbench
python -m benchmarks.redactionbench.run run     --data-dir benchmarks/data/redactionbench \
    --out-dir benchmarks/results/redactionbench
```

See [`../../redactionbench/README.md`](../../redactionbench/README.md) for the
full methodology, matching criteria, and output format.
