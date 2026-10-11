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


GREY = "#8a8a8a"


def _ci(path: str, system: str, metric: str) -> tuple[float, float, float]:
    v = json.loads((RAW / path).read_text())["scores"]["systems"][system]
    return v["point"][metric], *v["ci95"][metric]


def _dots(ax, rows, title: str, xlabel: str) -> None:
    for y, (_label, (pt, lo, hi), ours) in enumerate(reversed(rows)):
        color = COLOR["native"] if ours else GREY
        ax.plot([lo, hi], [y, y], color=color, lw=1.6)
        ax.plot(pt, y, "o", ms=6, color=color)
        ax.annotate(
            f"{pt:.3f}",
            (hi, y),
            xytext=(4, 0),
            textcoords="offset points",
            va="center",
            fontsize=7,
            color="#444444",
        )
    ax.set_yticks(range(len(rows)), [r[0] for r in reversed(rows)], fontsize=8)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel(xlabel, fontsize=8)
    ax.set_title(title, fontsize=9, loc="left")
    ax.grid(True, axis="x", color="#e4e4e4", lw=0.6)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def accuracy() -> None:
    sec = "2026-10-11_secrets_test_postfix_vs_scanners.json"
    pr_ss = "2026-10-11_presidio_research_test_postfix_ablation.json"
    pr_p = "2026-10-11_presidio_research_test.json"
    left = [
        ("SafeStream pattern", _ci(sec, "safestream-native", "entity_recall_covered"), True),
        ("SafeStream +spaCy", _ci(sec, "safestream-native-spacy", "entity_recall_covered"), True),
        ("gitleaks", _ci(sec, "gitleaks", "entity_recall_covered"), False),
        ("TruffleHog", _ci(sec, "trufflehog", "entity_recall_covered"), False),
        ("Presidio lg", _ci(sec, "presidio-lg", "entity_recall_covered"), False),
    ]
    right = [
        ("SafeStream pattern", _ci(pr_ss, "safestream-native", "char_f1"), True),
        ("SafeStream +spaCy (sm)", _ci(pr_ss, "safestream-native-spacy", "char_f1"), True),
        ("Presidio regex", _ci(pr_p, "presidio-regex", "char_f1"), False),
        ("Presidio sm", _ci(pr_p, "presidio-sm", "char_f1"), False),
        ("Presidio lg", _ci(pr_p, "presidio-lg", "char_f1"), False),
    ]
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    _dots(a, left, "(a) secrets test: fully redacted", "share of secrets, 95% CI")
    _dots(b, right, "(b) presidio-research test: char. F1", "character F1, 95% CI")
    fig.tight_layout()
    fig.savefig(OUT / "fig_accuracy.pdf")
    print("wrote", OUT / "fig_accuracy.pdf")


def scaling() -> None:
    part_b = json.loads((RAW / "2026-10-11_throughput_repeat.json").read_text())[
        "part_b_large_file"
    ]
    fig, ax = plt.subplots(figsize=(4.6, 3.2))
    workers = [1, 2, 4]
    for backend in ("native", "python"):
        rows = [part_b[f"{backend}/workers={w}"] for w in workers]
        means = [r["mean"] for r in rows]
        ax.errorbar(
            workers,
            means,
            yerr=[r["sd"] for r in rows],
            marker="o",
            ms=5,
            lw=1.6,
            capsize=3,
            color=COLOR[backend],
            label=f"{LABEL[backend]} ({rows[0]['file_mb']:.0f} MB file)",
        )
        ax.plot(workers, [means[0] * w for w in workers], ":", lw=1, color=COLOR[backend])
    ax.set_xticks(workers)
    ax.set_xlabel("Worker processes")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_yscale("log")
    ax.grid(True, which="major", color="#e4e4e4", lw=0.6)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(frameon=False, fontsize=8, title="dotted: linear scaling", title_fontsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "fig_scaling.pdf")
    print("wrote", OUT / "fig_scaling.pdf")


if __name__ == "__main__":
    memory()
    accuracy()
    scaling()
