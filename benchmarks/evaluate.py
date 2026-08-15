"""Accuracy evaluation against an INDEPENDENT, externally-labeled corpus.

Unlike ``run_benchmark.py`` (which scores against self-generated synthetic
text and therefore measures format coverage, not accuracy), this harness is
meant to be pointed at a corpus you did not generate — the Presidio research
dataset, CoNLL-2003, the n2c2/i2b2 de-identification set, or your own labeled
logs — so the resulting precision/recall are defensible real-world numbers.

Nothing is bundled (those corpora carry their own licenses); you supply the
data. Two input shapes are accepted:

1. ``--text corpus.txt --gold gold.json`` where ``gold.json`` is a list of
   ``{"start": int, "end": int, "type": str}`` spans into the text.
2. ``--jsonl records.jsonl`` where each line is
   ``{"text": str, "spans": [{"start", "end", "type"}, ...]}``.

External datasets label with their own type names, so map them onto SafeStream
entity types with ``--label-map`` (matching is type-aware). Only the mapped
types are scored, so a corpus that annotates only PERSON does not penalize
SafeStream for also detecting emails it never labeled.

Example (Presidio research dataset, converted to the jsonl shape)::

    python benchmarks/evaluate.py --jsonl presidio_eval.jsonl \\
        --label-map PERSON=person,EMAIL_ADDRESS=email,US_SSN=ssn,\\
US_PHONE_NUMBER=phone,CREDIT_CARD=credit_card,IP_ADDRESS=ipv4 --ner
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import tempfile
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from safestream_redactor import Calibrator, Redactor

Span = tuple[int, int, str]

# A system under evaluation: text in, predicted (start, end, safestream_type)
# spans out. SafeStream and every baseline are wrapped in one of these so the
# scorer treats them identically and comparisons are apples-to-apples.
Adapter = Callable[[str], list[Span]]


def spans_match(pred: tuple[int, int], gold: tuple[int, int]) -> bool:
    """A prediction hits a gold span when it overlaps at least 50% of it."""
    inter = min(pred[1], gold[1]) - max(pred[0], gold[0])
    return inter > 0 and inter >= 0.5 * (gold[1] - gold[0])


def score_record(
    gold: list[Span], preds: list[Span], eval_types: set[str]
) -> dict[str, tuple[int, int, int]]:
    """Per-type (tp, fp, fn) for one record, restricted to ``eval_types``."""
    gold_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in gold:
        if t in eval_types:
            gold_by_type[t].append((s, e))
    pred_by_type: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for s, e, t in preds:
        if t in eval_types:
            pred_by_type[t].append((s, e))

    out: dict[str, tuple[int, int, int]] = {}
    for t in eval_types:
        golds = gold_by_type.get(t, [])
        matched = set()
        tp = 0
        for ps, pe in pred_by_type.get(t, []):
            for i, g in enumerate(golds):
                if i not in matched and spans_match((ps, pe), g):
                    matched.add(i)
                    tp += 1
                    break
        fp = len(pred_by_type.get(t, [])) - tp
        fn = len(golds) - tp
        out[t] = (tp, fp, fn)
    return out


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def parse_label_map(spec: str) -> dict[str, str]:
    mapping = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        src, _, dst = pair.partition("=")
        if not dst:
            raise SystemExit(f"--label-map expects SRC=dst pairs, got {pair!r}")
        mapping[src.strip()] = dst.strip()
    return mapping


def load_records(args: argparse.Namespace) -> list[tuple[str, list[Span]]]:
    records: list[tuple[str, list[Span]]] = []
    if args.conll:
        return load_conll(Path(args.conll))
    if args.presidio_json:
        return load_presidio_json(Path(args.presidio_json))
    if args.jsonl:
        for line in Path(args.jsonl).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            spans = [(s["start"], s["end"], s["type"]) for s in obj.get("spans", [])]
            records.append((obj["text"], spans))
    else:
        if not (args.text and args.gold):
            raise SystemExit(
                "provide input: --jsonl, --conll, --presidio-json, or both --text and --gold"
            )
        text = Path(args.text).read_text(encoding="utf-8")
        gold = json.loads(Path(args.gold).read_text(encoding="utf-8"))
        records.append((text, [(g["start"], g["end"], g["type"]) for g in gold]))
    return records


# ---------------------------------------------------------------------------
# statistics: bootstrap confidence intervals and paired significance tests
# ---------------------------------------------------------------------------


def _micro_f1(per_record: list[dict[str, tuple[int, int, int]]], eval_types: set[str]) -> float:
    tp = fp = fn = 0
    for rec in per_record:
        for t in eval_types:
            a, b, c = rec.get(t, (0, 0, 0))
            tp += a
            fp += b
            fn += c
    return prf(tp, fp, fn)[2]


def bootstrap_f1_ci(
    per_record: list[dict[str, tuple[int, int, int]]],
    eval_types: set[str],
    *,
    resamples: int = 1000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Point micro-F1 and a bootstrap ``(1 - alpha)`` CI over records.

    Records are the resampling unit (sampling spans would break the tp/fp/fn
    coupling), so the interval reflects corpus-level uncertainty — the number a
    reviewer expects next to every headline F1.
    """
    point = _micro_f1(per_record, eval_types)
    if len(per_record) < 2:
        return point, point, point
    rng = random.Random(seed)
    n = len(per_record)
    stats = []
    for _ in range(resamples):
        sample = [per_record[rng.randrange(n)] for _ in range(n)]
        stats.append(_micro_f1(sample, eval_types))
    stats.sort()
    lo = stats[int((alpha / 2) * resamples)]
    hi = stats[min(resamples - 1, int((1 - alpha / 2) * resamples))]
    return point, lo, hi


def paired_bootstrap_pvalue(
    a_records: list[dict[str, tuple[int, int, int]]],
    b_records: list[dict[str, tuple[int, int, int]]],
    eval_types: set[str],
    *,
    resamples: int = 1000,
    seed: int = 0,
) -> float:
    """Two-sided paired-bootstrap p-value for ``F1(A) - F1(B)``.

    A and B must be scored on the *same* records in the same order (paired).
    Returns the fraction of resamples in which the F1 difference flips sign
    relative to the observed difference — a simple, assumption-light
    significance test suited to overlapping detector systems.
    """
    if len(a_records) != len(b_records):
        raise ValueError("paired test needs the same records for both systems")
    observed = _micro_f1(a_records, eval_types) - _micro_f1(b_records, eval_types)
    if len(a_records) < 2:
        return 1.0
    rng = random.Random(seed)
    n = len(a_records)
    flips = 0
    for _ in range(resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        diff = _micro_f1([a_records[i] for i in idx], eval_types) - _micro_f1(
            [b_records[i] for i in idx], eval_types
        )
        if (diff <= 0) if observed > 0 else (diff >= 0):
            flips += 1
    return min(1.0, 2 * flips / resamples)


# ---------------------------------------------------------------------------
# system adapters — SafeStream and the baselines reviewers will expect
# ---------------------------------------------------------------------------


def safestream_adapter(
    *, use_ner: bool = False, calibrator: Calibrator | None = None, min_confidence: float = 0.5
) -> Adapter:
    redactor = Redactor(use_ner=use_ner, calibrator=calibrator, min_confidence=min_confidence)

    def run(text: str) -> list[Span]:
        return [(d.start, d.end, d.entity_type.value) for d in redactor.detect(text)]

    return run


# A deliberately naive regex-only baseline: the "what a weekend script would
# do" reference that a real tool must beat. Always available (no dependency).
_BASELINE_REGEXES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("phone", re.compile(r"\+?\d[\d ().-]{7,}\d")),
)


def regex_baseline_adapter() -> Adapter:
    def run(text: str) -> list[Span]:
        out: list[Span] = []
        for label, rx in _BASELINE_REGEXES:
            out.extend((m.start(), m.end(), label) for m in rx.finditer(text))
        return out

    return run


# Presidio labels -> SafeStream types, so both are scored in one vocabulary.
_PRESIDIO_MAP = {
    "PERSON": "person",
    "EMAIL_ADDRESS": "email",
    "US_SSN": "ssn",
    "PHONE_NUMBER": "phone",
    "US_PHONE_NUMBER": "phone",
    "CREDIT_CARD": "credit_card",
    "IP_ADDRESS": "ipv4",
    "LOCATION": "loc",
    "ORGANIZATION": "org",
}


def presidio_adapter(*, nlp: bool = True) -> Adapter:
    """Microsoft Presidio in its strongest config (NER tier on by default).

    Requires the ``presidio-analyzer`` extra and a spaCy model; raises a clear
    error if unavailable rather than silently scoring nothing.
    """
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError as e:  # pragma: no cover - exercised only when installed
        raise SystemExit(
            "presidio baseline needs `pip install safestream-redactor[bench]` "
            "and a spaCy model (see the Presidio docs)"
        ) from e
    engine = AnalyzerEngine()

    def run(text: str) -> list[Span]:
        out: list[Span] = []
        for r in engine.analyze(text=text, language="en"):
            mapped = _PRESIDIO_MAP.get(r.entity_type)
            if mapped:
                out.append((r.start, r.end, mapped))
        return out

    return run


_SCRUBADUB_MAP = {"email": "email", "phone": "phone", "name": "person", "url": "url_credentials"}


def scrubadub_adapter() -> Adapter:
    """scrubadub, the standard PII reference."""
    try:
        import scrubadub
    except ImportError as e:  # pragma: no cover - exercised only when installed
        raise SystemExit("scrubadub baseline needs `pip install scrubadub`") from e
    scrubber = scrubadub.Scrubber()

    def run(text: str) -> list[Span]:
        out: list[Span] = []
        for f in scrubber.iter_filth(text):
            mapped = _SCRUBADUB_MAP.get(f.type)
            if mapped:
                out.append((f.beg, f.end, mapped))
        return out

    return run


def gitleaks_adapter(binary: str = "gitleaks") -> Adapter:
    """gitleaks, the secret-scanner competition for the credential claim.

    Shells out to the ``gitleaks`` binary per record (writing the text to a temp
    file), parses its JSON report, and locates each finding's secret to recover
    character offsets. Every finding maps to the generic ``secret`` type, since
    gitleaks' rule ids do not line up one-to-one with SafeStream's labels.
    """

    def run(text: str) -> list[Span]:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", encoding="utf-8") as tf:
            tf.write(text)
            tf.flush()
            with tempfile.NamedTemporaryFile("r", suffix=".json") as report:
                proc = subprocess.run(
                    [
                        binary,
                        "detect",
                        "--no-git",
                        "--source",
                        tf.name,
                        "--report-format",
                        "json",
                        "--report-path",
                        report.name,
                    ],
                    capture_output=True,
                )
                if proc.returncode not in (0, 1):  # 1 == leaks found
                    raise SystemExit(
                        f"gitleaks failed ({proc.returncode}); is the binary installed? "
                        f"{proc.stderr.decode(errors='replace')[:200]}"
                    )
                findings = json.loads(report.read() or "[]")
        out: list[Span] = []
        for f in findings:
            secret = f.get("Secret", "")
            pos = text.find(secret) if secret else -1
            if pos >= 0:
                out.append((pos, pos + len(secret), "secret"))
        return out

    return run


def build_adapter(name: str, args: argparse.Namespace) -> Adapter:
    if name == "safestream":
        calibrator = Calibrator.load(args.calibrator) if args.calibrator else None
        return safestream_adapter(
            use_ner=args.ner, calibrator=calibrator, min_confidence=args.min_confidence
        )
    if name == "regex":
        return regex_baseline_adapter()
    if name == "presidio":
        return presidio_adapter()
    if name == "scrubadub":
        return scrubadub_adapter()
    if name == "gitleaks":
        return gitleaks_adapter()
    raise SystemExit(f"unknown system {name!r}")


# ---------------------------------------------------------------------------
# corpus loaders for the standard public formats
# ---------------------------------------------------------------------------


def load_conll(path: Path) -> list[tuple[str, list[Span]]]:
    """CoNLL-2003 (``TOKEN POS CHUNK NER`` columns, BIO tags) -> records.

    Reconstructs one record per document (``-DOCSTART-`` boundaries, or the
    whole file if absent), joining tokens with single spaces and turning BIO
    spans into character offsets. CoNLL types map to SafeStream's ``person`` /
    ``org`` / ``loc`` (``MISC`` is dropped as out-of-scope).
    """
    conll_map = {"PER": "person", "ORG": "org", "LOC": "loc"}
    records: list[tuple[str, list[Span]]] = []
    tokens: list[str] = []
    spans: list[Span] = []
    cur_type: str | None = None  # raw CoNLL type ("PER"), mapped at flush time
    cur_start = 0
    pos = 0  # running text length == end offset of the last appended token

    def flush_entity(end: int) -> None:
        nonlocal cur_type
        if cur_type is not None:
            mapped = conll_map.get(cur_type)
            if mapped:
                spans.append((cur_start, end, mapped))
        cur_type = None

    def flush_record() -> None:
        nonlocal tokens, spans, pos, cur_type
        flush_entity(pos)
        if tokens:
            records.append((" ".join(tokens), spans))
        tokens, spans, pos, cur_type = [], [], 0, None

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("-DOCSTART-"):
            flush_record()
            continue
        if not line.strip():
            flush_entity(pos)  # sentence break ends any open entity
            continue
        parts = line.split()
        token, tag = parts[0], parts[-1]
        sep = 1 if tokens else 0  # a joining space precedes every token but the first
        token_start = pos + sep
        prefix, _, etype = tag.partition("-")
        if prefix == "B" or (prefix == "I" and etype != cur_type):
            flush_entity(pos)  # previous entity ended at the previous token's end
            cur_type, cur_start = etype, token_start
        elif prefix == "O":
            flush_entity(pos)
        # (prefix == "I" and etype == cur_type) just extends the open entity
        tokens.append(token)
        pos = token_start + len(token)
    flush_record()
    return records


def load_presidio_json(path: Path) -> list[tuple[str, list[Span]]]:
    """Presidio research dataset JSON -> records.

    Accepts the dataset's ``[{"full_text": ..., "spans": [{"entity_type",
    "start_position", "end_position"}]}]`` shape and emits raw (unmapped) span
    types, so ``--label-map`` still applies uniformly downstream.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    records: list[tuple[str, list[Span]]] = []
    for obj in data:
        text = obj.get("full_text", obj.get("text", ""))
        spans = [
            (s["start_position"], s["end_position"], s["entity_type"]) for s in obj.get("spans", [])
        ]
        records.append((text, spans))
    return records


# ---------------------------------------------------------------------------
# error analysis
# ---------------------------------------------------------------------------


def collect_errors(
    records: list[tuple[str, list[Span]]],
    adapter: Adapter,
    eval_types: set[str],
    *,
    limit: int = 10,
) -> dict[str, dict[str, list[str]]]:
    """False-negative and false-positive example snippets per type.

    The categorised examples are usually the part of a paper that earns the
    accept: they show *why* a tool misses or over-fires, not just that it does.
    """
    errors: dict[str, dict[str, list[str]]] = {t: {"fn": [], "fp": []} for t in eval_types}

    def snippet(text: str, s: int, e: int) -> str:
        return repr(text[max(0, s - 15) : e + 15])

    for text, gold in records:
        preds = [(s, e, t) for s, e, t in adapter(text) if t in eval_types]
        gold_t = [(s, e, t) for s, e, t in gold if t in eval_types]
        for gs, ge, gt in gold_t:
            missed = not any(pt == gt and spans_match((ps, pe), (gs, ge)) for ps, pe, pt in preds)
            if missed and len(errors[gt]["fn"]) < limit:
                errors[gt]["fn"].append(snippet(text, gs, ge))
        for ps, pe, pt in preds:
            spurious = not any(
                gt == pt and spans_match((ps, pe), (gs, ge)) for gs, ge, gt in gold_t
            )
            if spurious and len(errors[pt]["fp"]) < limit:
                errors[pt]["fp"].append(snippet(text, ps, pe))
    return errors


def score_all(
    records: list[tuple[str, list[Span]]], adapter: Adapter, eval_types: set[str]
) -> list[dict[str, tuple[int, int, int]]]:
    """Per-record tp/fp/fn for one system across the corpus."""
    return [score_record(gold, adapter(text), eval_types) for text, gold in records]


def _print_table(per_record: list[dict[str, tuple[int, int, int]]], eval_types: set[str]) -> None:
    print(f"{'type':<16}{'P':>8}{'R':>8}{'F1':>8}{'tp':>8}{'fp':>8}{'fn':>8}")
    micro = [0, 0, 0]
    for t in sorted(eval_types):
        tp = sum(r.get(t, (0, 0, 0))[0] for r in per_record)
        fp = sum(r.get(t, (0, 0, 0))[1] for r in per_record)
        fn = sum(r.get(t, (0, 0, 0))[2] for r in per_record)
        micro[0] += tp
        micro[1] += fp
        micro[2] += fn
        p, r, f = prf(tp, fp, fn)
        print(f"{t:<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}{tp:>8}{fp:>8}{fn:>8}")
    p, r, f = prf(*micro)
    print(f"{'MICRO-AVG':<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}{micro[0]:>8}{micro[1]:>8}{micro[2]:>8}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--jsonl", type=Path, help="records file (one JSON object per line)")
    ap.add_argument("--text", type=Path, help="corpus text file (with --gold)")
    ap.add_argument("--gold", type=Path, help="gold spans JSON (with --text)")
    ap.add_argument("--conll", type=Path, help="CoNLL-2003 formatted corpus")
    ap.add_argument("--presidio-json", type=Path, help="Presidio research dataset JSON")
    ap.add_argument(
        "--label-map",
        default="",
        help="comma-separated SRC=safestream_type pairs mapping the corpus's labels",
    )
    ap.add_argument("--ner", action="store_true", help="enable the spaCy NER tier")
    ap.add_argument(
        "--system",
        default="safestream",
        choices=["safestream", "regex", "presidio", "scrubadub", "gitleaks"],
        help="system under evaluation (default: safestream)",
    )
    ap.add_argument(
        "--compare",
        choices=["safestream", "regex", "presidio", "scrubadub", "gitleaks"],
        help="a second system to compare against, with a paired significance test",
    )
    ap.add_argument("--calibrator", type=Path, help="calibrator JSON for the safestream system")
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--bootstrap", type=int, default=1000, help="bootstrap resamples (0 disables)")
    ap.add_argument("--errors", type=int, default=0, help="show N error examples per type")
    args = ap.parse_args()

    label_map = parse_label_map(args.label_map)
    records = load_records(args)
    if label_map:
        records = [
            (text, [(s, e, label_map[t]) for s, e, t in spans if t in label_map])
            for text, spans in records
        ]
    eval_types = {t for _, spans in records for _, _, t in spans}
    if not eval_types:
        raise SystemExit("no gold spans after label mapping — check --label-map")

    adapter = build_adapter(args.system, args)
    per_record = score_all(records, adapter, eval_types)

    print(f"corpus: {len(records)} record(s), evaluated types: {', '.join(sorted(eval_types))}")
    print(f"system: {args.system}\n")
    _print_table(per_record, eval_types)

    if args.bootstrap:
        point, lo, hi = bootstrap_f1_ci(per_record, eval_types, resamples=args.bootstrap)
        print(f"\nmicro-F1 {point:.3f}  95% CI [{lo:.3f}, {hi:.3f}]  ({args.bootstrap} resamples)")

    if args.compare:
        b_adapter = build_adapter(args.compare, args)
        b_records = score_all(records, b_adapter, eval_types)
        a_f1 = _micro_f1(per_record, eval_types)
        b_f1 = _micro_f1(b_records, eval_types)
        pval = paired_bootstrap_pvalue(
            per_record, b_records, eval_types, resamples=args.bootstrap or 1000
        )
        print(
            f"\n{args.system} F1={a_f1:.3f}  vs  {args.compare} F1={b_f1:.3f}  "
            f"(Δ={a_f1 - b_f1:+.3f}, paired-bootstrap p={pval:.3f})"
        )

    if args.errors:
        print(f"\n--- error analysis (up to {args.errors} examples/type) ---")
        for t, kinds in sorted(
            collect_errors(records, adapter, eval_types, limit=args.errors).items()
        ):
            for kind in ("fn", "fp"):
                for ex in kinds[kind]:
                    print(f"  {t:<14} {kind.upper()}  {ex}")


if __name__ == "__main__":
    main()
