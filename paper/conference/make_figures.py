"""Tables and figures of the conference paper, generated only from raw results.

    python paper/conference/make_figures.py

Reads ``research/results/raw/conf/`` and writes ``content/tab_*.tex`` and
``figures/*.pdf``. Nothing is typed by hand: a table that cannot be filled from a
result file prints a red MISSING marker instead.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "research" / "results" / "raw" / "conf"
HERE = Path(__file__).resolve().parent
OUT_TEX = HERE / "content"
OUT_FIG = HERE / "figures"

SYSTEMS = [
    ("safestream-native", "T0"),
    ("safestream-native-onnx", "T0+NN"),
    ("safestream-native-onnx-ungated", "T0+NN ungated"),
    ("safestream-native-spacy", "T0+spaCy"),
    ("presidio-sm", "Presidio sm"),
    ("presidio-lg", "Presidio lg"),
]


def load(name: str) -> Any:
    path = RAW / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def missing(what: str) -> str:
    return rf"\MISSING{{{what}}}"


def f3(x: float) -> str:
    return f"{x:.3f}"


def ci(lo: float, hi: float) -> str:
    return f"[{lo:.3f}, {hi:.3f}]"


def table_accuracy() -> str:
    rows = []
    corp = [("ai4privacy", "ai4privacy"), ("wnut17", "WNUT-17"), ("conll2003", "CoNLL$^\\ast$")]
    data = {c: (load(f"E2_{c}_test.json"), load(f"E2_{c}_person.json")) for c, _ in corp}
    benign = load("E2_benign_test.json")
    for sys, label in SYSTEMS:
        cells = [label]
        for c, _ in corp:
            run, per = data[c]
            if not run or not per:
                cells.append(missing(c))
                continue
            p = per["systems"][sys]
            cells.append(
                rf"\pc{{{f3(p['char_recall'])}}}"
                rf"{{{p['char_recall_ci'][0]:.3f}, {p['char_recall_ci'][1]:.3f}}}"
            )
            if c != "conll2003":
                s = run["scores"]["systems"][sys]
                lo, hi = s["ci95"]["scope_char_f1"]
                cells.append(rf"\pc{{{f3(s['point']['scope_char_f1'])}}}{{{lo:.3f}, {hi:.3f}}}")
        w = data["wnut17"][0]["runs"][sys]
        cells += [f"{1000 * w['mb_s']:.1f}", f"{w['p50_ms']:.1f}"]
        cells.append(
            f"{benign['scores']['systems'][sys]['point']['fp_doc_rate']:.2f}"
            if benign
            else missing("benign")
        )
        rows.append(" & ".join(cells) + r" \\")
    head = (
        r"\begin{table*}[t]"
        "\n"
        r"\caption{Accuracy and cost (C-RQ1). PER R: person-name character recall; Scope F1: "
        r"character F1 over gold of the types Presidio can detect; 95\% document-level "
        r"intervals. kB/s and p50 (median ms per document) from the WNUT-17 run; FA: share of "
        r"the 55 benign documents with any detection. $^\ast$CoNLL-2003 is the neural model's "
        r"training distribution: an upper bound, not independent evidence.}\label{tab:accuracy}"
        "\n"
        r"\centering\footnotesize\setlength{\tabcolsep}{4pt}"
        "\n"
        r"\begin{adjustbox}{max width=\textwidth}\begin{tabular}{@{}l llllll rrr@{}}"
        "\n"
        r"\toprule"
        "\n"
        r" & \multicolumn{2}{c}{ai4privacy (synthetic)} & \multicolumn{2}{c}{WNUT-17 (real)} & "
        r"CoNLL$^\ast$ & & \multicolumn{3}{c}{Cost and false alarms}\\"
        "\n"
        r"System & PER R & Scope F1 & PER R & Scope F1 & PER R & & kB/s & p50 & FA \\"
        "\n"
        r"\midrule"
        "\n"
    )
    # an empty column keeps CoNLL apart from the cost block
    body = "\n".join(_insert_gap(r) for r in rows)
    return (
        head + body + "\n" + r"\bottomrule"
        "\n"
        r"\end{tabular}\end{adjustbox}"
        "\n"
        r"\end{table*}"
        "\n"
    )


def _insert_gap(row: str) -> str:
    cells = row.removesuffix(r" \\").split(" & ")
    return " & ".join([*cells[:6], "", *cells[6:]]) + r" \\"


def table_gate() -> str:
    g = load("E1_gate.json")
    c = load("E5_context.json")
    if not g:
        return missing("E1 gate") + "\n"
    names = [
        ("ai4privacy", "ai4privacy"),
        ("wnut17", "WNUT-17"),
        ("conll2003", "CoNLL$^\\ast$"),
        ("benign", "Benign prose"),
        ("loghub", "Loghub logs"),
    ]
    rows = []
    for key, label in names:
        r = g["gate"][key]
        rec = r["gate_recall"]["PERSON"]
        flips = c["context"].get(key) if c else None
        flip = (
            f"{flips['flips']['128']}/{flips['flips']['256']} of {flips['detections']:,}"
            if flips
            else "--"
        )
        rows.append(
            f"{label} & {r['pass_rate']:.3f} & {f3(rec) if rec is not None else '--'} & "
            f"{r['window_len_max']} & {r['windows_over_declared']} & {flip} \\\\"
        )
    return (
        r"\begin{table}[t]"
        "\n"
        r"\caption{The gate and the declared context (C-RQ2). Pass: share of characters sent "
        r"to the model. Gate R: share of gold person names lying entirely inside some window, "
        r"the ceiling on the tier's recall. Max: longest merged window; $>$256: windows longer "
        r"than the declared context. Flips: detections that disappear when only 128 / 256 "
        r"characters are kept on each side of them, out of all detections of the tier on up to "
        r"200 documents.}\label{tab:gate}"
        "\n"
        r"\centering\footnotesize\setlength{\tabcolsep}{4pt}"
        "\n"
        r"\begin{tabular}{@{}l r r r r l@{}}"
        "\n"
        r"\toprule"
        "\n"
        r"Corpus & Pass & Gate R & Max & $>$256 & Flips (128/256) \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(rows) + "\n"
        r"\bottomrule"
        "\n"
        r"\end{tabular}"
        "\n"
        r"\end{table}"
        "\n"
    )


def table_egress() -> str:
    pre, post = load("E6_egress_prefix.json"), load("E6_egress_postfix.json")
    if not pre or not post:
        return missing("E6 egress pre/post") + "\n"
    rows = []
    for tier, tl in [
        ("pattern", "T0"),
        ("gazetteer", "T0+gazetteer"),
        ("onnx", "T0+NN"),
        ("spacy", "T0+spaCy"),
    ]:
        cells = [tl]
        for corpus in ("agent_traces", "wnut17", "ai4privacy"):
            a = pre["results"][f"{tier}|{corpus}"]
            b = post["results"][f"{tier}|{corpus}"]
            cells.append(f"{a['values_egressed']:,} / {b['values_egressed']:,}")
        rows.append(" & ".join(cells) + r" \\")
    n = {
        c: pre["results"][f"pattern|{c}"]["values_checked"]
        for c in ("agent_traces", "wnut17", "ai4privacy")
    }
    return (
        r"\begin{table}[t]"
        "\n"
        r"\caption{Egress through content-free replies (C-RQ3): distinct gold values found in "
        r"any content-free reply, before / after the fix. Values searched per tier: AgentTrace "
        + f"{n['agent_traces']:,}, WNUT-17 {n['wnut17']:,}, ai4privacy {n['ai4privacy']:,}."
        + r"}\label{tab:egress}"
        "\n"
        r"\centering\footnotesize"
        "\n"
        r"\begin{tabular}{@{}l r r r@{}}"
        "\n"
        r"\toprule"
        "\n"
        r"Tiers & AgentTrace & WNUT-17 & ai4privacy \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(rows) + "\n"
        r"\bottomrule"
        "\n"
        r"\end{tabular}"
        "\n"
        r"\end{table}"
        "\n"
    )


def table_cost() -> str:
    lat = load("E8_latency.json")
    lat_pre = load("E8_latency_rest_prefix.json")
    pol = load("E9_policy.json")
    if not lat or not pol:
        return missing("E8 latency / E9 policy") + "\n"
    sizes = [256, 4096, 65536, 1 << 20, 4 << 20]
    names = {
        256: "256\\,B",
        4096: "4\\,KiB",
        65536: "64\\,KiB",
        1 << 20: "1\\,MiB",
        4 << 20: "4\\,MiB",
    }
    rows = []
    for s in sizes:
        r = lat["results"]
        cells = [names[s]]
        for tr in ("inproc", "stdio", "rest"):
            cells.append(f"{r[f'{tr}|{s}']['p50_ms']:.2f}")
        pr = lat_pre["results"].get(f"rest|{s}") if lat_pre else None
        cells.append(f"{pr['p50_ms']:.2f}" if pr else "--")
        rows.append(" & ".join(cells) + r" \\")
    o = pol["overhead"]
    modes = ["replace", "mask", "hash", "pseudonymize", "encrypt", "fictionalize"]
    mrows = [
        f"{m} & {o[m]['e2e_mb_s']:.2f} & {o[m]['render_us_per_detection']:.2f} & "
        f"{o[m]['inflation']:.3f} \\\\"
        for m in modes
    ]
    return (
        r"\begin{table}[t]"
        "\n"
        r"\caption{Cost per tool call and per redaction mode (C-RQ4). Upper block: median "
        r"milliseconds per \texttt{scan} call on AgentTrace text, by transport; REST before "
        r"the Nagle fix in the last column. Lower block: end-to-end MB/s of \texttt{redact}, "
        r"microseconds per detection to render the replacement, and bytes out per byte in.}"
        r"\label{tab:cost}"
        "\n"
        r"\centering\footnotesize\setlength{\tabcolsep}{4pt}"
        "\n"
        r"\begin{tabular}{@{}l r r r r@{}}"
        "\n"
        r"\toprule"
        "\n"
        r"Payload & In-process & stdio & REST & REST (pre-fix) \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(rows) + "\n"
        r"\midrule"
        "\n"
        r"Mode & MB/s & $\mu$s/det. & Inflation & \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(r.replace(r" \\", r" & \\") for r in mrows) + "\n"
        r"\bottomrule"
        "\n"
        r"\end{tabular}"
        "\n"
        r"\end{table}"
        "\n"
    )


def table_thirdparty() -> str:
    a = load("E11_thirdparty_traces_wnut.json")
    b = load("E11_thirdparty_ai4privacy500.json")
    if not a or not b:
        return missing("E11 third-party audit") + "\n"
    rows = []
    tools = sorted({k.split("|")[0] for k in a["results"]}, key=lambda t: (t == "safestream", t))
    for t in tools:
        role = ("redact", "scan") if t == "safestream" else ("anonymize", "detect")

        def frac(r: dict, tool: str, field: str) -> str:
            x = r["results"].get(tool)
            return f"{x[field] / x['values_checked']:.2f}" if x else "--"

        at, wn = a["results"][f"{t}|agent_traces"], a["results"][f"{t}|wnut17"]
        ai = b["results"][f"{t}|ai4privacy"]
        rest = at.get("restore")
        restore = "--"
        if rest:
            got = max(rest["recovered"].values())
            restore = f"{got:,}/{rest['values_hidden']:,}"
        label = "SafeStream" if t == "safestream" else t
        rows.append(
            f"{label} & {frac(at, role[0], 'values_in_redacted_text')} & "
            f"{frac(wn, role[0], 'values_in_redacted_text')} & "
            f"{frac(ai, role[0], 'values_in_redacted_text')} & "
            f"{frac(at, role[0], 'values_in_other_fields')} & "
            f"{frac(at, role[1], 'values_in_other_fields')} & {restore} \\\\"
        )
    return (
        r"\begin{table}[t]"
        "\n"
        r"\caption{Third-party agent-facing redaction tools (C-RQ5), pseudonymised until their "
        r"maintainers have been told. Left: share of gold values left in the tool's "
        r"redacted output (a recall measure) on AgentTrace (AT), WNUT-17 (WN) and 500 "
        r"ai4privacy documents (AI). Map: share returned elsewhere in the same reply. "
        r"Detect: share returned by the tool's detection call. Restore: hidden values the "
        r"agent got back by calling the tool's own restore call, on AgentTrace.}"
        r"\label{tab:thirdparty}"
        "\n"
        r"\centering\footnotesize\setlength{\tabcolsep}{3pt}"
        "\n"
        r"\begin{adjustbox}{max width=\columnwidth}\begin{tabular}{@{}l rrr rr r@{}}"
        "\n"
        r"\toprule"
        "\n"
        r" & \multicolumn{3}{c}{Left in output} & & & \\"
        "\n"
        r"Tool & AT & WN & AI & Map & Detect & Restore \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(rows) + "\n"
        r"\bottomrule"
        "\n"
        r"\end{tabular}\end{adjustbox}"
        "\n"
        r"\end{table}"
        "\n"
    )


def table_agent() -> str:
    d = load("E12_agent_injection.json")
    if not d:
        return missing("E12 agent experiment") + "\n"
    tools = sorted({k.split("|")[0] for k in d["results"]}, key=lambda t: (t != "safestream", t))
    rows = []
    for t in tools:
        cells = ["SafeStream" if t == "safestream" else t]
        for metric in ("reached_model", "in_answer", "restore_called"):
            for cond in ("benign", "injected"):
                m = d["results"][f"{t}|{cond}"][metric]
                cells.append(f"{m['runs']}/{m['of']}")
        rows.append(" & ".join(cells) + r" \\")
    return (
        r"\begin{table}[t]"
        "\n"
        r"\caption{A local LLM agent (Qwen2.5-7B-Instruct) asked to summarise a ticket it "
        r"may read only through each redaction tool (C-RQ6), "
        + f"{d['n_docs']} tickets per condition. "
        r"Reached: runs in which a value the tool had hidden reached the model through a tool "
        r"result; Answer: in the final answer; Restore: runs in which the agent called a "
        r"restore tool. B: benign ticket; I: ticket with an appended prompt injection.}"
        r"\label{tab:agent}"
        "\n"
        r"\centering\footnotesize\setlength{\tabcolsep}{3pt}"
        "\n"
        r"\begin{tabular}{@{}l rr rr rr@{}}"
        "\n"
        r"\toprule"
        "\n"
        r" & \multicolumn{2}{c}{Reached} & \multicolumn{2}{c}{Answer} & "
        r"\multicolumn{2}{c}{Restore} \\"
        "\n"
        r"Tool & B & I & B & I & B & I \\"
        "\n"
        r"\midrule"
        "\n" + "\n".join(rows) + "\n"
        r"\bottomrule"
        "\n"
        r"\end{tabular}"
        "\n"
        r"\end{table}"
        "\n"
    )


def figure_recall_cost() -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.4), sharey=True)
    for ax, (c, title) in zip(
        axes, [("wnut17", "WNUT-17 (real)"), ("ai4privacy", "ai4privacy (synthetic)")], strict=True
    ):
        run, per = load(f"E2_{c}_test.json"), load(f"E2_{c}_person.json")
        for sys, label in SYSTEMS:
            ms = run["runs"][sys]["p50_ms"]
            p = per["systems"][sys]
            lo, hi = p["char_recall_ci"]
            ax.errorbar(
                ms,
                p["char_recall"],
                yerr=[[p["char_recall"] - lo], [hi - p["char_recall"]]],
                fmt="o",
                ms=4,
                capsize=2,
                color="black" if "safestream" in sys else "gray",
            )
            ax.annotate(
                label,
                (ms, p["char_recall"]),
                xytext=(4, 3),
                textcoords="offset points",
                fontsize=6.5,
            )
        ax.set_xscale("log")
        ax.set_title(title, fontsize=8)
        ax.set_xlabel("median ms per document (log)", fontsize=7)
        ax.tick_params(labelsize=7)
    axes[0].set_ylabel("person-name char. recall", fontsize=7)
    fig.tight_layout()
    OUT_FIG.mkdir(exist_ok=True)
    fig.savefig(OUT_FIG / "fig_recall_cost.pdf", metadata={"CreationDate": None})


def main() -> None:
    for name, fn in [
        ("tab_accuracy", table_accuracy),
        ("tab_gate", table_gate),
        ("tab_egress", table_egress),
        ("tab_cost", table_cost),
        ("tab_thirdparty", table_thirdparty),
        ("tab_agent", table_agent),
    ]:
        (OUT_TEX / f"{name}.tex").write_text(fn(), encoding="utf-8")
        print("wrote", name)
    figure_recall_cost()
    print("wrote fig_recall_cost.pdf")


if __name__ == "__main__":
    main()
