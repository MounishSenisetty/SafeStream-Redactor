"""One evaluation harness: every system, every corpus, same scorer, with CIs.

    python -m benchmarks.harness --corpus presidio_research --split dev \\
        --systems safestream-native presidio-regex presidio-sm --bootstrap 2000

Each system runs in its own subprocess, so load time, throughput and peak RSS are
per system and never cross-contaminated. The parent scores every system's spans
against the same gold with the same code and writes raw JSON (with an environment
block: CPU, cores, power state, versions, commit) plus a markdown table.

Metrics (each per document, summed, so documents are the bootstrap unit):

* **char** P/R/F1 -- type-agnostic, over the union of gold vs predicted characters;
  the headline for a redactor (did the sensitive characters get hidden?).
* **entity recall (covered)** -- a gold span counts only when *every* character is
  redacted by some prediction (a half-masked SSN still leaks).
* **entity P/R/F1, partial** (>=50% of the gold span overlapped, one-to-one) and
  **strict** (exact offsets), both type-agnostic and type-aware per canonical type.
* **mandatory recall** and **no-leak document rate** where the corpus labels
  necessity (RedactionBench).
* throughput (MB/s over analysis time, load excluded), p50/p99 per-document latency,
  load time, peak RSS and tool RSS (peak minus the process after loading the data).

95% CIs are percentile bootstrap over documents; paired differences between two
systems use the same resamples for both.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata as md
import json
import os
import platform
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks import corpora  # noqa: E402

Pred = tuple[int, int, str]
ONNX_DIR = ROOT / "models" / "ner"
PRESIDIO_PIECE = 20_000  # spaCy refuses >1M chars and grows with length: feed pieces
TRANSFORMERS_MODEL = os.environ.get("PRESIDIO_TRANSFORMERS_MODEL", "dslim/bert-base-NER")

# name -> (tier, safestream Redactor kwargs | None for Presidio)
_ONNX = {
    "use_onnx": True,
    "onnx_model": str(ONNX_DIR / "model.int8.onnx"),
    "onnx_vocab": str(ONNX_DIR / "tokenizer.json"),
    "onnx_labels": str(ONNX_DIR / "labels.json"),
}
SYSTEMS: dict[str, tuple[str, dict[str, Any] | None]] = {
    "safestream-python": ("pattern", {"backend": "python"}),
    "safestream-native": ("pattern", {"backend": "native"}),
    "safestream-native-dates": ("pattern", {"backend": "native", "use_dates": True}),
    "safestream-native-onnx": ("ner", {"backend": "native", **_ONNX}),
    "safestream-native-onnx-dates": ("ner", {"backend": "native", "use_dates": True, **_ONNX}),
    "safestream-native-spacy": ("ner", {"backend": "native", "use_ner": True}),
    "presidio-regex": ("pattern", None),
    "presidio-sm": ("ner", None),
    "presidio-lg": ("ner", None),
    "presidio-transformers": ("ner", None),
}


# --- systems (run inside the child process) ------------------------------------


def _safestream(kwargs: dict[str, Any]) -> Callable[[str], list[Pred]]:
    from safestream_redactor import Redactor

    redactor = Redactor(load_plugins=False, **kwargs)
    to_canon = corpora.SAFESTREAM_TO_CANONICAL

    def analyze(text: str) -> list[Pred]:
        # the streaming engine, as files and pipes are processed in practice
        out: list[Pred] = []
        offset = 0
        chunks = (text[i : i + 65536] for i in range(0, len(text), 65536))
        for segment, detections in redactor.detect_stream(chunks):
            for d in detections:
                t = d.entity_type.value
                out.append((offset + d.start, offset + d.end, to_canon.get(t, t.upper())))
            offset += len(segment)
        return out

    return analyze


def _pieces(text: str, size: int = PRESIDIO_PIECE) -> list[tuple[int, str]]:
    out, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            nl = text.rfind("\n", start, end)
            end = nl + 1 if nl > start else end
        out.append((start, text[start:end]))
        start = end
    return out


def _presidio(name: str) -> Callable[[str], list[Pred]]:
    import logging

    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry

    if name == "presidio-regex":
        # Presidio's rule recognizers called directly: no NLP engine, so spaCy is
        # neither loaded nor timed. Context boosting needs NLP artifacts and only
        # re-ranks scores; no threshold is applied, so the span set is unchanged.
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(languages=["en"])
        ml = ("Spacy", "Stanza", "Transformers", "GLiNER")
        recognizers = [r for r in registry.recognizers if not type(r).__name__.startswith(ml)]

        def run(piece: str) -> list[tuple[int, int, str]]:
            res = []
            for rec in recognizers:
                for r in rec.analyze(piece, rec.supported_entities, nlp_artifacts=None) or []:
                    res.append((r.start, r.end, r.entity_type))
            return res

    else:
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        if name == "presidio-transformers":
            config: dict[str, Any] = {
                "nlp_engine_name": "transformers",
                "models": [
                    {
                        "lang_code": "en",
                        "model_name": {
                            "spacy": "en_core_web_sm",
                            "transformers": TRANSFORMERS_MODEL,
                        },
                    }
                ],
            }
        else:
            model = {"presidio-sm": "en_core_web_sm", "presidio-lg": "en_core_web_lg"}[name]
            config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            }
        engine = AnalyzerEngine(
            nlp_engine=NlpEngineProvider(nlp_configuration=config).create_engine(),
            supported_languages=["en"],
        )

        def run(piece: str) -> list[tuple[int, int, str]]:
            return [(r.start, r.end, r.entity_type) for r in engine.analyze(piece, language="en")]

    def analyze(text: str) -> list[Pred]:
        return [
            (off + s, off + e, corpora.presidio_to_canonical(t))
            for off, piece in _pieces(text)
            for s, e, t in run(piece)
        ]

    return analyze


def _peak_rss_mb() -> float:
    if sys.platform == "win32":
        import psutil

        return float(psutil.Process().memory_info().peak_wset) / 2**20
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / 2**20 if sys.platform == "darwin" else peak / 1024


def _rss_mb() -> float:
    import psutil

    return float(psutil.Process().memory_info().rss) / 2**20


def run_one(system: str, corpus: str, split: str) -> dict[str, Any]:
    docs = corpora.load(corpus, split).docs
    base_rss = _rss_mb()  # the data alone: subtracted to get the tool's own memory
    t0 = time.perf_counter()
    _tier, kwargs = SYSTEMS[system]
    analyze = _safestream(kwargs) if kwargs is not None else _presidio(system)
    analyze("Warm up: John Smith, john@example.com, 4111 1111 1111 1111.")
    load_s = time.perf_counter() - t0
    preds, per_doc = [], []
    for d in docs:
        t = time.perf_counter()
        preds.append(analyze(d.text))
        per_doc.append(time.perf_counter() - t)
    peak = _peak_rss_mb()
    return {
        "system": system,
        "load_s": load_s,
        "per_doc_s": per_doc,
        "bytes": sum(len(d.text.encode("utf-8")) for d in docs),
        "peak_rss_mb": peak,
        "tool_rss_mb": peak - base_rss,
        "preds": preds,
    }


# --- scoring -------------------------------------------------------------------

AGNOSTIC = "*"  # the type-agnostic pseudo-type in per-type counters


def _partial_hit(p: tuple[int, int], g: tuple[int, int]) -> bool:
    inter = min(p[1], g[1]) - max(p[0], g[0])
    return inter > 0 and inter >= 0.5 * (g[1] - g[0])


def _match(golds: list[tuple[int, int]], preds: list[tuple[int, int]]) -> tuple[int, int]:
    """(partial tp, strict tp): one-to-one greedy matching, preds in order."""
    used: set[int] = set()
    partial = 0
    for p in preds:
        for i, g in enumerate(golds):
            if i not in used and _partial_hit(p, g):
                used.add(i)
                partial += 1
                break
    remaining = list(golds)
    strict = 0
    for p in preds:
        if p in remaining:
            remaining.remove(p)
            strict += 1
    return partial, strict


def score_doc(doc: corpora.Doc, preds: list[Pred]) -> dict[str, float]:
    """Additive counters for one document (so the bootstrap can resample docs)."""
    n = len(doc.text)
    gold_mask = bytearray(n)
    pred_mask = bytearray(n)
    for g in doc.spans:
        gold_mask[g.start : g.end] = b"\x01" * (g.end - g.start)
    for s, e, _t in preds:
        s, e = max(0, s), min(n, e)
        if e > s:
            pred_mask[s:e] = b"\x01" * (e - s)
    gold_c = gold_mask.count(1)
    pred_c = pred_mask.count(1)
    tp_c = sum(1 for a, b in zip(gold_mask, pred_mask, strict=True) if a and b)
    c: dict[str, float] = {
        "char_tp": tp_c,
        "char_fp": pred_c - tp_c,
        "char_fn": gold_c - tp_c,
        "ent_total": len(doc.spans),
        "ent_covered": sum(1 for g in doc.spans if all(pred_mask[g.start : g.end])),
    }
    mand = [g for g in doc.spans if g.necessity == "mandatory"]
    if mand:
        m_mask = bytearray(n)
        for g in mand:
            m_mask[g.start : g.end] = b"\x01" * (g.end - g.start)
        m_total = m_mask.count(1)
        m_cov = sum(1 for a, b in zip(m_mask, pred_mask, strict=True) if a and b)
        c |= {"mand_total": m_total, "mand_cov": m_cov, "mand_docs": 1}
        c["mand_noleak_docs"] = int(m_cov == m_total)
    types = {g.type for g in doc.spans} | {t for _s, _e, t in preds}
    for t in [AGNOSTIC, *types]:
        golds = [(g.start, g.end) for g in doc.spans if t in (AGNOSTIC, g.type)]
        ps = [(s, e) for s, e, pt in preds if t in (AGNOSTIC, pt)]
        partial, strict = _match(golds, ps)
        c[f"{t}|gold"] = len(golds)
        c[f"{t}|pred"] = len(ps)
        c[f"{t}|tp_partial"] = partial
        c[f"{t}|tp_strict"] = strict
    return c


def _ratio(a: Any, b: Any) -> Any:
    import numpy as np

    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    return np.divide(a, b, out=np.zeros_like(a), where=b > 0)


def _f1(p: Any, r: Any) -> Any:
    return _ratio(2 * p * r, p + r)


HEADLINE = (
    "char_p",
    "char_r",
    "char_f1",
    "entity_recall_covered",
    "ent_p_partial",
    "ent_r_partial",
    "ent_f1_partial",
    "ent_f1_strict",
    "mandatory_recall",
    "no_leak_doc_rate",
)


def metrics(get: Callable[[str], Any]) -> dict[str, Any]:
    """Headline metrics from summed counters (``get(key)`` -> scalar or array)."""
    char_p = _ratio(get("char_tp"), get("char_tp") + get("char_fp"))
    char_r = _ratio(get("char_tp"), get("char_tp") + get("char_fn"))
    out = {"char_p": char_p, "char_r": char_r, "char_f1": _f1(char_p, char_r)}
    out["entity_recall_covered"] = _ratio(get("ent_covered"), get("ent_total"))
    for kind in ("partial", "strict"):
        p = _ratio(get(f"{AGNOSTIC}|tp_{kind}"), get(f"{AGNOSTIC}|pred"))
        r = _ratio(get(f"{AGNOSTIC}|tp_{kind}"), get(f"{AGNOSTIC}|gold"))
        out |= {f"ent_p_{kind}": p, f"ent_r_{kind}": r, f"ent_f1_{kind}": _f1(p, r)}
    out["mandatory_recall"] = _ratio(get("mand_cov"), get("mand_total"))
    out["no_leak_doc_rate"] = _ratio(get("mand_noleak_docs"), get("mand_docs"))
    return out


def evaluate(
    docs: list[corpora.Doc],
    runs: dict[str, list[list[Pred]]],
    *,
    resamples: int = 2000,
    seed: int = 0,
) -> dict[str, Any]:
    """Point estimates, bootstrap CIs, per-type tables and paired differences."""
    import numpy as np

    counters = {
        name: [score_doc(d, p) for d, p in zip(docs, preds, strict=True)]
        for name, preds in runs.items()
    }
    keys = sorted({k for cs in counters.values() for c in cs for k in c})
    col = {k: i for i, k in enumerate(keys)}
    mats = {
        name: np.array([[c.get(k, 0) for k in keys] for c in cs], dtype=float)
        for name, cs in counters.items()
    }
    rng = np.random.default_rng(seed)
    n = len(docs)
    # one shared resample matrix: CIs and paired differences use the same draws
    weights = (
        np.stack([np.bincount(rng.integers(0, n, n), minlength=n) for _ in range(resamples)])
        if n and resamples
        else None
    )

    result: dict[str, Any] = {}
    boot: dict[str, dict[str, Any]] = {}
    for name, mat in mats.items():
        total = mat.sum(0)
        point = {
            k: float(v)
            for k, v in metrics(lambda key, t=total: t[col[key]] if key in col else 0.0).items()
        }
        ci: dict[str, list[float]] = {}
        if weights is not None:
            sums = weights @ mat  # resamples x counters
            boot[name] = metrics(
                lambda key, s=sums: s[:, col[key]] if key in col else np.zeros(len(s))
            )
            ci = {
                k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
                for k, v in boot[name].items()
            }
        per_type = {}
        for t in sorted({k.split("|")[0] for k in keys if "|" in k} - {AGNOSTIC}):
            g, p = total[col[f"{t}|gold"]], total[col[f"{t}|pred"]]
            row = {"gold": int(g), "pred": int(p)}
            for kind in ("partial", "strict"):
                tp = total[col[f"{t}|tp_{kind}"]]
                pr, rc = (tp / p if p else 0.0), (tp / g if g else 0.0)
                row |= {
                    f"p_{kind}": pr,
                    f"r_{kind}": rc,
                    f"f1_{kind}": (2 * pr * rc / (pr + rc) if pr + rc else 0.0),
                }
            per_type[t] = row
        result[name] = {"point": point, "ci95": ci, "per_type": per_type}

    paired: dict[str, dict[str, list[float]]] = {}
    names = list(mats)
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            if a in boot and b in boot:
                paired[f"{a} - {b}"] = {
                    k: [float(np.percentile(boot[a][k] - boot[b][k], q)) for q in (2.5, 50, 97.5)]
                    for k in HEADLINE
                }
    return {"systems": result, "paired_diff_ci95": paired}


# --- environment ---------------------------------------------------------------


def _cpu_name() -> str:
    if sys.platform == "win32":
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        )
        return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
    if sys.platform == "darwin":
        return subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
        ).stdout.strip()
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def environment() -> dict[str, Any]:
    import psutil

    battery = psutil.sensors_battery()
    versions = {}
    for dist in (
        "safestream-redactor",
        "safestream-redactor-native",
        "presidio-analyzer",
        "spacy",
        "en-core-web-sm",
        "en-core-web-lg",
        "onnxruntime",
        "tokenizers",
        "transformers",
        "torch",
        "numpy",
    ):
        try:
            versions[dist] = md.version(dist)
        except md.PackageNotFoundError:
            versions[dist] = None

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()

    return {
        "date": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "cpu": _cpu_name(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "power": "no battery (AC)"
        if battery is None
        else ("AC" if battery.power_plugged else f"BATTERY ({battery.percent:.0f}%)"),
        "os": platform.platform(),
        "python": platform.python_version(),
        "versions": versions,
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
    }


# --- driver --------------------------------------------------------------------


def _fmt_ci(point: float, ci: list[float] | None) -> str:
    return f"{point:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else f"{point:.3f}"


def markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    lines = [
        f"## {report['corpus']} / {report['split']} ({report['n_docs']} docs)",
        "",
        f"{env['date']} | {env['cpu']} ({env['physical_cores']}C/{env['logical_cores']}T) | "
        f"power: {env['power']} | Python {env['python']} | commit {env['commit'][:10]}"
        f"{' (dirty)' if env['dirty'] else ''}",
        "",
    ]
    if report.get("previously_exposed"):
        lines += [f"> **Previously exposed:** {report['previously_exposed']}", ""]
    has_mand = any(s["point"]["mandatory_recall"] for s in report["scores"]["systems"].values())
    head = (
        "| System | Tier | Char P | Char R | Char F1 | Entity R (covered) "
        "| Ent F1 partial | Ent F1 strict |"
    )
    sep = "|---|---|---|---|---|---|---|---|"
    if has_mand:
        head += " Mandatory R | No-leak docs |"
        sep += "---|---|"
    head += " MB/s | p50 / p99 ms | Load s | Peak / tool RSS MB |"
    sep += "---|---|---|---|"
    lines += [head, sep]
    for name, run in report["runs"].items():
        if "skipped" in run:
            lines.append(f"| {name} | {SYSTEMS[name][0]} | skipped: {run['skipped']} |")
            continue
        s = report["scores"]["systems"][name]
        cell = [
            _fmt_ci(s["point"][k], s["ci95"].get(k))
            for k in (
                "char_p",
                "char_r",
                "char_f1",
                "entity_recall_covered",
                "ent_f1_partial",
                "ent_f1_strict",
            )
        ]
        if has_mand:
            cell += [
                _fmt_ci(s["point"][k], s["ci95"].get(k))
                for k in ("mandatory_recall", "no_leak_doc_rate")
            ]
        cell += [
            f"{run['mb_s']:.3f}",
            f"{run['p50_ms']:.1f} / {run['p99_ms']:.1f}",
            f"{run['load_s']:.1f}",
            f"{run['peak_rss_mb']:.0f} / {run['tool_rss_mb']:.0f}",
        ]
        lines.append(f"| {name} | {SYSTEMS[name][0]} | " + " | ".join(cell) + " |")
    lines += ["", "Per type (partial-match entity P / R, gold count):", ""]
    systems = [n for n in report["runs"] if "skipped" not in report["runs"][n]]
    types = sorted(
        {
            t
            for n in systems
            for t in report["scores"]["systems"][n]["per_type"]
            if report["scores"]["systems"][n]["per_type"][t]["gold"]
        }
    )
    lines += ["| Type | Gold | " + " | ".join(systems) + " |", "|---|---|" + "---|" * len(systems)]
    for t in types:
        rows = [report["scores"]["systems"][n]["per_type"].get(t, {}) for n in systems]
        gold = next((r["gold"] for r in rows if r), 0)
        lines.append(
            f"| {t} | {gold} | "
            + " | ".join(f"{r.get('p_partial', 0):.2f} / {r.get('r_partial', 0):.2f}" for r in rows)
            + " |"
        )
    if report.get("corpus_skipped"):
        lines += [
            "",
            f"Loader notes: {len(report['corpus_skipped'])} gold item(s) adjusted or unplaceable "
            "(listed in the JSON).",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--run-one", nargs=3, metavar=("SYSTEM", "CORPUS", "SPLIT"), help=argparse.SUPPRESS
    )
    ap.add_argument("--corpus", choices=sorted(corpora.LOADERS))
    ap.add_argument("--split", default="dev", choices=("dev", "test", "all"))
    ap.add_argument("--systems", nargs="+", default=list(SYSTEMS), choices=list(SYSTEMS))
    ap.add_argument("--bootstrap", type=int, default=2000, help="resamples (0 disables CIs)")
    ap.add_argument(
        "--json", type=Path, help="raw results file (default: research/results/raw/...)"
    )
    ap.add_argument("--md", type=Path, help="also write the markdown table here")
    args = ap.parse_args()
    if args.run_one:
        json.dump(run_one(*args.run_one), sys.stdout)
        return
    if not args.corpus:
        ap.error("--corpus is required")

    corpus = corpora.load(args.corpus, args.split)
    env = environment()
    runs: dict[str, dict[str, Any]] = {}
    preds: dict[str, list[list[Pred]]] = {}
    for system in args.systems:
        print(f"# {args.corpus}/{args.split}: {system} ...", file=sys.stderr, flush=True)
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "benchmarks.harness",
                "--run-one",
                system,
                args.corpus,
                args.split,
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            encoding="utf-8",
        )
        if proc.returncode != 0:
            reason = (proc.stderr.strip().splitlines() or ["failed"])[-1]
            print(f"#   skipped: {reason}", file=sys.stderr)
            runs[system] = {"skipped": reason}
            continue
        run = json.loads(proc.stdout)
        preds[system] = [[tuple(p) for p in doc] for doc in run.pop("preds")]
        lat = sorted(run.pop("per_doc_s"))
        analyze_s = sum(lat)
        run |= {
            "analyze_s": analyze_s,
            "mb_s": run["bytes"] / 1e6 / analyze_s if analyze_s else 0.0,
            "p50_ms": 1000 * lat[len(lat) // 2] if lat else 0.0,
            "p99_ms": 1000 * lat[min(len(lat) - 1, int(0.99 * len(lat)))] if lat else 0.0,
        }
        runs[system] = run
    manifest = corpora.SPLITS / f"{args.corpus}.json"
    report = {
        "corpus": args.corpus,
        "split": args.split,
        "n_docs": len(corpus.docs),
        "source_revision": corpus.revision,
        "previously_exposed": json.loads(manifest.read_text())["previously_exposed"]
        if manifest.exists() and args.split != "all"
        else None,
        "corpus_notes": corpus.notes,
        "corpus_skipped": corpus.skipped,
        "environment": env,
        "systems": {s: SYSTEMS[s][0] for s in args.systems},
        "runs": runs,
        "scores": evaluate(corpus.docs, preds, resamples=args.bootstrap),
        "command": " ".join([Path(sys.executable).name, "-m", "benchmarks.harness", *sys.argv[1:]]),
    }
    out = args.json or ROOT / "research" / "results" / "raw" / (
        f"{dt.date.today().isoformat()}_{args.corpus}_{args.split}.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    table = markdown(report)
    print(table)
    if args.md:
        args.md.write_text(table, encoding="utf-8")
    print(f"# wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
