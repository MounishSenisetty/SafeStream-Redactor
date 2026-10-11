"""Build the paper's figures from the raw result files (run from the repo root).

python paper/journal/make_figures.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW = Path("research/results/raw")
OUT = Path(__file__).resolve().parent
COLOR = {"native": "#2a78d6", "python": "#eb6834"}  # validated categorical pair
LABEL = {"native": "Rust core", "python": "pure Python"}


def memory() -> None:
    rows = []
    for f in sorted(RAW.glob("2026-10-11_memory_curve_*.jsonl")):
        rows += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    fig, ax = plt.subplots(figsize=(6.0, 3.6))
    for mode, style, marker in (("stream", "-", "o"), ("whole", "--", "s")):
        for backend in ("native", "python"):
            pts = sorted(
                (r["size_mb"], r["delta_mb"])
                for r in rows
                if r["mode"] == mode and r["backend"] == backend
            )
            if not pts:
                continue
            xs, ys = zip(*pts, strict=True)
            name = "streaming redact_file" if mode == "stream" else "whole-document redact()"
            ax.plot(
                xs,
                ys,
                style,
                marker=marker,
                ms=5,
                lw=1.6,
                color=COLOR[backend],
                label=f"{name}, {LABEL[backend]}",
            )
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Input size (MiB)")
    ax.set_ylabel("Peak RSS added by redaction (MB)")
    ax.grid(True, which="major", color="#e4e4e4", lw=0.6)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "fig_memory.pdf")
    print("wrote", OUT / "fig_memory.pdf", len(rows), "points")


if __name__ == "__main__":
    memory()
