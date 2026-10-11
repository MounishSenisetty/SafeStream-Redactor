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
import shutil
import subprocess
import sys
import tempfile
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
PRESIDIO_PIECE = 20_000
# Every system runs on one thread so per-core throughput is like-for-like (the
# ONNX tier is single-threaded; torch would otherwise use every core).
# Multi-core scaling is measured separately (benchmarks/parallel_speedup.py).
THREADS = 1
_THREAD_ENV = {
    k: str(THREADS)
    for k in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "TORCH_NUM_THREADS")
}  # spaCy refuses >1M chars and grows with length: feed pieces
# Presidio's transformers engine with two MIT-licensed models: the de-identification
# model Presidio's docs use as their example, and a general-purpose NER model.
TRANSFORMERS_MODELS = {
    "presidio-trf-deid": "StanfordAIMI/stanford-deidentifier-base",
    "presidio-trf-bert": "dslim/bert-base-NER",
}

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
    # the "prose" detection profile (documents rather than logs)
    "safestream-native-prose": ("pattern", {"backend": "native", "profile": "prose"}),
    "safestream-native-onnx": ("ner", {"backend": "native", **_ONNX}),
    # opt-in batched inference: faster, but output depends on chunking (INT8)
    "safestream-native-onnx-batched": (
        "ner",
        {"backend": "native", "onnx_batch_size": 32, **_ONNX},
    ),
    "safestream-native-onnx-dates": ("ner", {"backend": "native", "use_dates": True, **_ONNX}),
    "safestream-native-onnx-prose": ("ner", {"backend": "native", "profile": "prose", **_ONNX}),
    "safestream-native-spacy": ("ner", {"backend": "native", "use_ner": True}),
    "presidio-regex": ("pattern", None),
    "presidio-sm": ("ner", None),
    "presidio-lg": ("ner", None),
    "presidio-trf-deid": ("ner", None),
    "presidio-trf-bert": ("ner", None),
}

# Ablations (pure-Python backend: byte-identical to native, but its tiers are
# separate detectors that can be dropped one at a time). "_drop" removes detectors
# by name; "_greedy" replaces the NER union rule with plain best-first selection.
_ALL_T0 = ("deterministic", "labeled_identifier", "entropy", "compound_secret", "contextual")
_ABLATIONS: dict[str, dict[str, Any]] = {
    "abl-full": {},
    "abl-no-entropy": {"use_entropy": False},
    "abl-no-labeled": {"_drop": ("labeled_identifier",)},
    "abl-no-contextual": {"_drop": ("contextual",)},
    "abl-only-deterministic": {"_drop": tuple(n for n in _ALL_T0 if n != "deterministic")},
    "abl-only-labeled": {"_drop": tuple(n for n in _ALL_T0 if n != "labeled_identifier")},
    "abl-only-entropy": {"_drop": ("deterministic", "labeled_identifier", "contextual")},
    "abl-only-contextual": {"_drop": tuple(n for n in _ALL_T0 if n != "contextual")},
    "abl-only-spacy": {"use_ner": True, "_drop": _ALL_T0},
    "abl-full-spacy": {"use_ner": True},
    "abl-full-spacy-greedy": {"use_ner": True, "_greedy": True},
}
for _name, _kw in _ABLATIONS.items():
    SYSTEMS[_name] = ("ner" if _kw.get("use_ner") else "pattern", {"backend": "python", **_kw})

# Purpose-built secret scanners, run once over a folder with one file per document
# (their CLIs are batch tools; per-document process start-up would dominate).
# TruffleHog runs with --no-verification: no example secret is ever sent to an API.
SCANNERS = {
    "gitleaks": [
        os.environ.get("GITLEAKS", "gitleaks"),
        "dir",
        "{dir}",
        "--report-format",
        "json",
        "--report-path",
        "{out}",
        "--no-banner",
        "--log-level",
        "error",
        "--exit-code",
        "0",
    ],
    "trufflehog": [
        os.environ.get("TRUFFLEHOG", "trufflehog"),
        "filesystem",
        "{dir}",
        "--json",
        "--no-verification",
        "--no-update",
        "--log-level=-1",
    ],
}
SYSTEMS |= {name: ("pattern", None) for name in SCANNERS}


# --- systems (run inside the child process) ------------------------------------


def _safestream(kwargs: dict[str, Any]) -> Callable[[str], list[Pred]]:
    from safestream_redactor import Redactor

    kwargs = dict(kwargs)
    drop = set(kwargs.pop("_drop", ()))
    if kwargs.pop("_greedy", False):
        from safestream_redactor import entities
        from safestream_redactor import redactor as redactor_mod

        redactor_mod.resolve_overlaps = entities._greedy  # ablation: no NER union rule
    redactor = Redactor(load_plugins=False, **kwargs)
    if drop:
        missing = drop - {d.name for d in redactor._detectors}
        assert not missing, f"ablation names unknown detectors: {missing}"
        redactor._detectors = [d for d in redactor._detectors if d.name not in drop]
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

        if name in TRANSFORMERS_MODELS:
            model_name = {"spacy": "en_core_web_sm", "transformers": TRANSFORMERS_MODELS[name]}
            config: dict[str, Any] = {
                "nlp_engine_name": "transformers",
                "models": [{"lang_code": "en", "model_name": model_name}],
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
        if name in TRANSFORMERS_MODELS:
            import torch

            torch.set_num_threads(THREADS)  # like-for-like with the 1-thread tools

        def run(piece: str) -> list[tuple[int, int, str]]:
            return [(r.start, r.end, r.entity_type) for r in engine.analyze(piece, language="en")]

    def analyze(text: str) -> list[Pred]:
        return [
            (off + s, off + e, corpora.presidio_to_canonical(t))
            for off, piece in _pieces(text)
            for s, e, t in run(piece)
        ]

    return analyze


def _place(text: str, secret: str, line: int | None, col: int | None) -> tuple[int, int] | None:
    """Character span of a scanner's reported secret: on its line, nearest its column."""
    if not secret:
        return None
    if line:
        starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
        if line <= len(starts):
            lo = starts[line - 1]
            hits = [m for m in _find_all(text, secret) if m >= lo]
            near = lo + max(0, (col or 1) - 1)
            if hits:
                s = min(hits, key=lambda m: abs(m - near))
                return s, s + len(secret)
    hits = _find_all(text, secret)
    return (hits[0], hits[0] + len(secret)) if hits else None


def _find_all(text: str, sub: str) -> list[int]:
    out, i = [], text.find(sub)
    while i >= 0:
        out.append(i)
        i = text.find(sub, i + 1)
    return out


def _scan_batch(name: str, texts: list[str]) -> tuple[list[list[Pred]], float, int]:
    """(predictions per doc, wall seconds for the whole run, findings left unplaced)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "docs"
        root.mkdir()
        for i, text in enumerate(texts):
            (root / f"{i:06d}.txt").write_text(text, encoding="utf-8", newline="")
        out = Path(tmp) / "report.json"
        cmd = [a.format(dir=root, out=out) for a in SCANNERS[name]]
        t = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
        wall = time.perf_counter() - t
        if name == "gitleaks":
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr[-500:])
            findings = [
                (Path(f["File"]).name, f["Secret"], f["StartLine"], f["StartColumn"])
                for f in json.loads(out.read_text(encoding="utf-8") or "[]")
            ]
        else:
            import re

            def docs_text(fname: str) -> str:
                return texts[int(Path(fname).stem)]

            findings = []
            for line in proc.stdout.splitlines():
                if not line.startswith("{"):
                    continue
                f = json.loads(line)
                fs = f.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                if "file" not in fs:
                    continue
                raw = f.get("Raw") or ""
                findings.append((Path(fs["file"]).name, raw, fs.get("line"), None))
                # RawV2 is TruffleHog's own composite (``user:token``, a rebuilt
                # connection URI), usually not literal text: credit each component
                # of 8+ characters that does appear in the document
                v2 = f.get("RawV2") or ""
                parts = [v2] if v2 in docs_text(fs["file"]) else re.split(r"[:@;/?&=]", v2)
                findings += [
                    (Path(fs["file"]).name, p, fs.get("line"), None)
                    for p in parts
                    if len(p) >= 8 and p != raw and p in docs_text(fs["file"])
                ]
    preds: list[list[Pred]] = [[] for _ in texts]
    unplaced = 0
    for fname, secret, line, col in findings:
        i = int(Path(fname).stem)
        span = _place(texts[i], secret, line, col)
        if span is None:
            unplaced += 1
        else:
            preds[i].append((*span, "SECRET"))
    return preds, wall, unplaced


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


def run_one(system: str, texts_path: str) -> dict[str, Any]:
    # The parent wrote just this split's texts: parsing a whole corpus here
    # (ai4privacy's file is mostly token columns) would put the loader's peak
    # into every tool's memory high-water mark.
    texts: list[str] = json.loads(Path(texts_path).read_text(encoding="utf-8"))
    base_rss = _rss_mb()  # the data alone: subtracted to get the tool's own memory
    if system in SCANNERS:
        # external binary: its memory is not this process's, so RSS is not reported;
        # time is one wall-clock run (start-up included) spread evenly over documents
        preds, wall, unplaced = _scan_batch(system, texts)
        return {
            "system": system,
            "load_s": 0.0,
            "per_doc_s": [wall / max(1, len(texts))] * len(texts),
            "bytes": sum(len(t.encode("utf-8")) for t in texts),
            "peak_rss_mb": None,
            "tool_rss_mb": None,
            "timing": "one batch run including process start-up, divided evenly",
            "unplaced_findings": unplaced,
            "tool_version": subprocess.run(
                [SCANNERS[system][0], "--version"], capture_output=True, text=True, check=False
            ).stdout.strip()
            or subprocess.run(
                [SCANNERS[system][0], "version"], capture_output=True, text=True, check=False
            ).stdout.strip(),
            "threads": None,
            "power_at_end": _power(),
            "preds": preds,
        }
    t0 = time.perf_counter()
    _tier, kwargs = SYSTEMS[system]
    analyze = _safestream(kwargs) if kwargs is not None else _presidio(system)
    analyze("Warm up: John Smith, john@example.com, 4111 1111 1111 1111.")
    load_s = time.perf_counter() - t0
    preds, per_doc = [], []
    for text in texts:
        t = time.perf_counter()
        preds.append(analyze(text))
        per_doc.append(time.perf_counter() - t)
    peak = _peak_rss_mb()
    return {
        "system": system,
        "load_s": load_s,
        "per_doc_s": per_doc,
        "bytes": sum(len(t.encode("utf-8")) for t in texts),
        "peak_rss_mb": peak,
        "tool_rss_mb": peak - base_rss,
        # audit trail: what this process actually ran with. A heavy framework
        # pulled in by an unrelated install inflates load time and memory.
        "python": sys.executable,
        "versions": _versions(),
        "heavy_modules_loaded": sorted(m for m in _HEAVY if m in sys.modules),
        "threads": THREADS,
        "power_at_end": _power(),
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
    if not doc.spans:  # a gold-free document: any detection on it is a false alarm
        c |= {"neg_docs": 1, "neg_flagged": int(bool(preds))}
    # Presidio-scope: only gold Presidio can detect. Characters of other gold
    # count neither as hits nor as false alarms.
    scope = [g for g in doc.spans if g.type in corpora.PRESIDIO_SCOPE]
    out_mask = bytearray(n)
    for g in doc.spans:
        if g.type not in corpora.PRESIDIO_SCOPE:
            out_mask[g.start : g.end] = b"\x01" * (g.end - g.start)
    s_mask = bytearray(n)
    for g in scope:
        s_mask[g.start : g.end] = b"\x01" * (g.end - g.start)
    s_tp = sum(1 for a, b in zip(s_mask, pred_mask, strict=True) if a and b)
    s_fp = sum(
        1 for a, b, o in zip(s_mask, pred_mask, out_mask, strict=True) if b and not a and not o
    )
    c |= {
        "scope_tp": s_tp,
        "scope_fp": s_fp,
        "scope_fn": s_mask.count(1) - s_tp,
        "scope_ent_total": len(scope),
        "scope_ent_full": sum(1 for g in scope if all(pred_mask[g.start : g.end])),
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
    "fp_doc_rate",
    "scope_char_f1",
    "scope_fully_redacted",
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
    out["fp_doc_rate"] = _ratio(get("neg_flagged"), get("neg_docs"))
    sp = _ratio(get("scope_tp"), get("scope_tp") + get("scope_fp"))
    sr = _ratio(get("scope_tp"), get("scope_tp") + get("scope_fn"))
    out |= {"scope_char_p": sp, "scope_char_r": sr, "scope_char_f1": _f1(sp, sr)}
    out["scope_fully_redacted"] = _ratio(get("scope_ent_full"), get("scope_ent_total"))
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


def sample_errors(
    docs: list[corpora.Doc], preds: list[list[Pred]], limit: int, context: int = 40
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Up to ``limit`` misses and false alarms per type, with surrounding text.

    A miss is a gold span not fully redacted (it leaks); a false alarm is a
    prediction that touches no gold character. For error analysis on *dev*
    splits only, and never committed for corpora whose licence forbids
    redistribution.
    """
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def add(t: str, kind: str, doc: corpora.Doc, s: int, e: int, covered: int = 0) -> None:
        bucket = out.setdefault(t, {"missed": [], "false_alarm": []})[kind]
        if len(bucket) < limit:
            bucket.append(
                {
                    "doc": doc.doc_id,
                    "span": doc.text[s:e],
                    "covered_chars": covered,
                    "context": doc.text[max(0, s - context) : e + context],
                }
            )

    for doc, ps in zip(docs, preds, strict=True):
        mask = bytearray(len(doc.text))
        for s, e, _t in ps:
            mask[max(0, s) : max(0, e)] = b"\x01" * (max(0, e) - max(0, s))
        gold = bytearray(len(doc.text))
        for g in doc.spans:
            gold[g.start : g.end] = b"\x01" * (g.end - g.start)
            covered = sum(mask[g.start : g.end])
            if covered < g.end - g.start:
                add(g.type, "missed", doc, g.start, g.end, covered)
        for s, e, t in ps:
            if not any(gold[max(0, s) : max(0, e)]):
                add(t, "false_alarm", doc, s, e)
    return out


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


_DISTS = (
    "safestream-redactor",
    "safestream-redactor-native",
    "presidio-analyzer",
    "spacy",
    "spacy-huggingface-pipelines",
    "en-core-web-sm",
    "en-core-web-lg",
    "onnxruntime",
    "tokenizers",
    "transformers",
    "torch",
    "numpy",
)
_HEAVY = ("torch", "transformers", "spacy", "onnxruntime", "tensorflow", "gliner", "stanza")


def _versions() -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for dist in _DISTS:
        try:
            out[dist] = md.version(dist)
        except md.PackageNotFoundError:
            out[dist] = None
    return out


def _power() -> str:
    import psutil

    battery = psutil.sensors_battery()
    if battery is None:
        return "no battery (AC)"
    return "AC" if battery.power_plugged else f"BATTERY ({battery.percent:.0f}%)"


_WIN_POWER_MODES = {  # Windows 11 power-mode overlays (Settings > Power > Power mode)
    "961cc777-2547-4f9d-8174-7d86181b8a7a": "Best power efficiency",
    "00000000-0000-0000-0000-000000000000": "Balanced",
    "ded574b5-45a0-4f42-8737-46345c09c238": "Best performance",
}


def _power_plan() -> str | None:
    """Power scheme plus the Windows 11 power mode, which throttles the CPU on its own."""
    if sys.platform != "win32":
        return None
    import winreg

    out = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True, text=True)
    scheme = out.stdout.strip().split("(")[-1].rstrip(")")
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
        )
        mode = str(winreg.QueryValueEx(key, "ActiveOverlayAcPowerScheme")[0]).lower()
    except OSError:
        return scheme
    return f"{scheme}; AC power mode: {_WIN_POWER_MODES.get(mode, mode)}"


def environment() -> dict[str, Any]:
    import multiprocessing

    import psutil

    versions = _versions()

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=ROOT
        ).stdout.strip()

    return {
        "date": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "cpu": _cpu_name(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "power": _power(),
        "power_plan": _power_plan(),
        "os": platform.platform(),
        # Windows/macOS spawn worker processes (no fork): each worker re-imports
        # and reloads its models, which matters for parallel memory and startup
        "multiprocessing_start_method": multiprocessing.get_start_method(),
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
    has_mand = report.get("has_necessity", False)
    has_neg = report.get("has_negatives", False)
    has_scope = report.get("has_scope", False)
    head = (
        "| System | Tier | Char P | Char R | Char F1 | Entity R (covered) "
        "| Ent F1 partial | Ent F1 strict |"
    )
    sep = "|---|---|---|---|---|---|---|---|"
    if has_mand:
        head += " Mandatory R | No-leak docs |"
        sep += "---|---|"
    if has_neg:
        head += " FP doc rate |"
        sep += "---|"
    if has_scope:
        head += " Char F1 (Presidio-scope) | Fully redacted (Presidio-scope) |"
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
        if has_neg:
            cell.append(_fmt_ci(s["point"]["fp_doc_rate"], s["ci95"].get("fp_doc_rate")))
        if has_scope:
            cell += [
                _fmt_ci(s["point"][k], s["ci95"].get(k))
                for k in ("scope_char_f1", "scope_fully_redacted")
            ]
        cell += [
            f"{run['mb_s']:.3g}",
            f"{run['p50_ms']:.1f} / {run['p99_ms']:.1f}",
            f"{run['load_s']:.1f}",
            "n/a (external binary)"
            if run["peak_rss_mb"] is None
            else f"{run['peak_rss_mb']:.0f} / {run['tool_rss_mb']:.0f}",
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


def _interpreter(system: str, venv_root: Path | None) -> str:
    if venv_root is None:
        return sys.executable
    family = (
        "safestream"
        if SYSTEMS[system][1] is not None or system in SCANNERS
        else ("presidio-trf" if system in TRANSFORMERS_MODELS else "presidio")
    )
    sub = "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    return str(venv_root / family / sub)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--run-one", nargs=2, metavar=("SYSTEM", "TEXTS_JSON"), help=argparse.SUPPRESS)
    ap.add_argument("--corpus", choices=sorted(corpora.LOADERS))
    ap.add_argument("--split", default="dev", choices=("dev", "test", "all"))
    ap.add_argument("--systems", nargs="+", default=list(SYSTEMS), choices=list(SYSTEMS))
    ap.add_argument("--bootstrap", type=int, default=2000, help="resamples (0 disables CIs)")
    ap.add_argument(
        "--json", type=Path, help="raw results file (default: research/results/raw/...)"
    )
    ap.add_argument("--md", type=Path, help="also write the markdown table here")
    ap.add_argument(
        "--allow-battery",
        action="store_true",
        help="run on battery anyway (accuracy is valid; speed and latency are not)",
    )
    ap.add_argument(
        "--errors",
        type=int,
        default=0,
        metavar="N",
        help="write up to N missed / false-alarm examples per type per system to "
        "--errors-out (dev splits only; contains corpus text, never commit it)",
    )
    ap.add_argument("--errors-out", type=Path, help="where --errors writes its JSON")
    ap.add_argument(
        "--checkpoint-dir",
        type=Path,
        help="save each finished system run here and resume from it (same clean commit "
        "only), so an interrupted run loses at most one system",
    )
    ap.add_argument(
        "--venv-root",
        type=Path,
        help="run each system family in its own virtualenv under this folder "
        "(safestream/, presidio/, presidio-trf/), so no tool pays for another's "
        "dependencies; default: this interpreter for every system",
    )
    args = ap.parse_args()
    if args.run_one:
        json.dump(run_one(*args.run_one), sys.stdout)
        return
    if not args.corpus:
        ap.error("--corpus is required")

    corpus = corpora.load(args.corpus, args.split)
    env = environment()
    if not env["power"].endswith("AC)") and env["power"] != "AC" and not args.allow_battery:
        ap.error(
            f"power is {env['power']}: throughput, latency and load time measured on "
            "battery are not comparable. Plug in, or pass --allow-battery for an "
            "accuracy-only run."
        )
    runs: dict[str, dict[str, Any]] = {}
    preds: dict[str, list[list[Pred]]] = {}
    texts_dir = Path(tempfile.mkdtemp(prefix="safestream-harness-"))
    texts_path = texts_dir / f"{args.corpus}_{args.split}.json"
    texts_path.write_text(json.dumps([d.text for d in corpus.docs]), encoding="utf-8")
    ckpt_dir = args.checkpoint_dir
    if ckpt_dir:
        ckpt_dir.mkdir(parents=True, exist_ok=True)
    for system in args.systems:
        ckpt = ckpt_dir / f"{args.corpus}_{args.split}_{system}.json" if ckpt_dir else None
        if ckpt and ckpt.exists():
            saved = json.loads(ckpt.read_text(encoding="utf-8"))
            if saved.get("commit") == env["commit"] and not env["dirty"]:
                print(f"# {args.corpus}/{args.split}: {system} (resumed)", file=sys.stderr)
                run = saved["run"]
                preds[system] = [[tuple(p) for p in doc] for doc in run.pop("preds")]
                runs[system] = run
                continue
            print(f"# {system}: checkpoint is from another commit, re-running", file=sys.stderr)
        print(f"# {args.corpus}/{args.split}: {system} ...", file=sys.stderr, flush=True)
        proc = subprocess.run(
            [
                _interpreter(system, args.venv_root),
                "-m",
                "benchmarks.harness",
                "--run-one",
                system,
                str(texts_path),
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            encoding="utf-8",
            errors="replace",  # a stray byte in a library warning must not kill the reader
            # children write UTF-8 even where the console code page is cp1252 (Windows)
            env={**os.environ, **_THREAD_ENV, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
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
        if ckpt:  # one finished (system, corpus, split) survives an interruption
            ckpt.write_text(
                json.dumps({"commit": env["commit"], "run": {**run, "preds": preds[system]}}),
                encoding="utf-8",
            )
    shutil.rmtree(texts_dir, ignore_errors=True)  # corpus text never outlives the run
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
        "has_necessity": any(g.necessity == "mandatory" for d in corpus.docs for g in d.spans),
        "has_negatives": any(not d.spans for d in corpus.docs),
        "has_scope": any(g.type in corpora.PRESIDIO_SCOPE for d in corpus.docs for g in d.spans),
        "environment": env,
        "isolated_venvs": str(args.venv_root) if args.venv_root else None,
        "systems": {s: SYSTEMS[s][0] for s in args.systems},
        "runs": runs,
        "scores": evaluate(corpus.docs, preds, resamples=args.bootstrap),
        "command": " ".join([Path(sys.executable).name, "-m", "benchmarks.harness", *sys.argv[1:]]),
    }
    if args.errors:
        if args.split == "test":
            ap.error("--errors is for dev splits: looking at test errors is tuning on test")
        errors = {n: sample_errors(corpus.docs, p, args.errors) for n, p in preds.items()}
        target = args.errors_out or Path(f"errors_{args.corpus}_{args.split}.json")
        target.write_text(json.dumps(errors, indent=1, ensure_ascii=False), encoding="utf-8")
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
