"""Error taxonomy of remaining semantic false negatives on RedactionBench.

For every *mandatory* name-like (class-B) gold span the core+gazetteer pipeline
misses, record the span, its context, why each detector missed it, and a category
(the 12 requested buckets), then judge whether the miss is realistically solvable
by local heuristics/ensembles or fundamentally needs a statistical model. spaCy
coverage is read from a cache (``/tmp/spacy_preds.json``) when present so the slow
model is not re-run here.

Run: python -m benchmarks.redactionbench.error_analysis
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from safestream_redactor import Redactor
from safestream_redactor.detectors.name_data import COMMON_GIVEN_NAMES, HONORIFICS, NAME_CUES

from . import loader

_NAME_RE = re.compile(r"[A-Z][A-Za-zÀ-ÿ'.\-]*(\s+[A-Z][A-Za-zÀ-ÿ'.\-]*)*")
_CUE_WORDS = {w for w in NAME_CUES} | {h for h in HONORIFICS} | {"mr", "mrs", "ms", "dr"}
_ENGLISH_WORDS = {
    # a small set of capitalized-at-sentence-start / common words that also look
    # like names or proper nouns (months, directions, generic nouns)
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "north",
    "south",
    "east",
    "west",
    "spring",
    "summer",
    "fall",
    "winter",
    "the",
    "report",
    "system",
    "data",
    "note",
    "page",
    "date",
    "name",
    "total",
    "state",
    "city",
}


def _is_name_like(v: str) -> bool:
    return bool(_NAME_RE.fullmatch(v.strip())) and not v.strip().isdigit()


def _script(v: str) -> str:
    for ch in v:
        if ord(ch) < 128:
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name or "HANGUL" in name:
            return "cjk"
        if "CYRILLIC" in name:
            return "cyrillic"
        if "ARABIC" in name:
            return "arabic"
        if "LATIN" in name:  # accented latin
            return "accented"
    return "ascii"


def categorize(v: str, left: str, tokens: list[str]) -> str:
    s = v.strip()
    script = _script(s)
    if script in ("cjk", "cyrillic", "arabic"):
        return "04_non_latin_translit"
    if script == "accented":
        return "03_accented"
    if any("_" in t or "@" in t or any(c.isdigit() for c in t) for t in tokens):
        return "10_username_handle"
    low = s.lower()
    if any(t.lower().rstrip(".") in _ENGLISH_WORDS for t in tokens):
        return "08_word_like"
    if re.search(r"\b[A-Z]\.", s):
        return "05_initials"
    if len(tokens) == 1:
        # single token: given-only or surname-only fragment
        return "09_partial_single_token" if low not in COMMON_GIVEN_NAMES else "01_ordinary"
    if len(tokens) >= 4:
        return "06_long_multitoken"
    if tokens[0].lower() in COMMON_GIVEN_NAMES:
        return "01_ordinary"
    return "02_uncommon_rare"


def main() -> int:
    rows_r = loader.load_from_directory(
        Path("benchmarks/data/redactionbench"), loader.FieldSpec()
    ).records
    rows = [
        {
            "raw_text": r.text,
            "spans": [{"start": s.start, "end": s.end, "label": s.label} for s in r.spans],
        }
        for r in rows_r
    ]
    red = Redactor(use_gazetteer=True)
    spacy_cache: list[list[list[int]]] | None = None
    cache_path = Path("/tmp/spacy_preds.json")
    if cache_path.exists():
        spacy_cache = json.loads(cache_path.read_text())

    cat_count: Counter[str] = Counter()
    cat_chars: Counter[str] = Counter()
    cat_spacy_caught: Counter[str] = Counter()
    cat_cue_nearby: Counter[str] = Counter()
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    total_name_spans = 0
    total_missed = 0

    for i, r in enumerate(rows):
        t = r["raw_text"]
        n = len(t)
        pm = bytearray(n)
        for d in red.detect(t):
            for j in range(d.start, d.end):
                if 0 <= j < n:
                    pm[j] = 1
        sm = bytearray(n)
        if spacy_cache is not None:
            for s0, e0, _ in spacy_cache[i]:
                for j in range(s0, e0):
                    if 0 <= j < n:
                        sm[j] = 1
        for s in r["spans"]:
            if s["label"] != "mandatory":
                continue
            v = t[s["start"] : s["end"]]
            if not _is_name_like(v):
                continue
            total_name_spans += 1
            L = s["end"] - s["start"]
            covered = sum(pm[j] for j in range(s["start"], s["end"]) if j < n)
            if covered >= 0.5 * L:
                continue  # gazetteer got it
            total_missed += 1
            left = t[max(0, s["start"] - 30) : s["start"]]
            tokens = v.strip().split()
            cat = categorize(v, left, tokens)
            cat_count[cat] += 1
            cat_chars[cat] += L
            spacy_caught = spacy_cache is not None and (
                sum(sm[j] for j in range(s["start"], s["end"]) if j < n) >= 0.5 * L
            )
            if spacy_caught:
                cat_spacy_caught[cat] += 1
            cue_nearby = any(w in left.lower() for w in _CUE_WORDS)
            if cue_nearby:
                cat_cue_nearby[cat] += 1
            if len(examples[cat]) < 6:
                examples[cat].append({"gold": v[:30], "left": left[-24:], "spacy": spacy_caught})

    print(f"name-like mandatory spans: {total_name_spans}; missed by gazetteer: {total_missed}\n")
    print(
        f"{'category':<26}{'misses':>7}{'chars':>7}{'spaCy✓':>8}{'cueNear':>8}  solvable-locally?"
    )
    solvable = {
        "01_ordinary": "maybe (bigger name gazetteer)",
        "02_uncommon_rare": "no (needs model/large lexicon)",
        "03_accented": "partly (unicode name lexicon)",
        "04_non_latin_translit": "no (needs multilingual model)",
        "05_initials": "partly (pattern)",
        "06_long_multitoken": "maybe (capitalization + cue)",
        "08_word_like": "no (needs disambiguation model)",
        "09_partial_single_token": "partly (repeated-mention propagation)",
        "10_username_handle": "partly (cue/pattern)",
    }
    for cat, cnt in sorted(cat_count.items()):
        sc = cat_spacy_caught.get(cat, 0)
        print(
            f"{cat:<26}{cnt:>7}{cat_chars[cat]:>7}{sc:>8}{cat_cue_nearby.get(cat, 0):>8}  "
            f"{solvable.get(cat, '?')}"
        )
    print("\n=== examples ===")
    for cat in sorted(examples):
        print(f"\n{cat}:")
        for ex in examples[cat]:
            print(f"   gold={ex['gold']!r:34} left=...{ex['left']!r:26} spaCy_caught={ex['spacy']}")
    if spacy_cache is not None:
        tot_sc = sum(cat_spacy_caught.values())
        both = total_missed - tot_sc
        pct = 100 * tot_sc / max(1, total_missed)
        print(
            f"\nOf {total_missed} gazetteer misses, spaCy caught {tot_sc} ({pct:.0f}%); "
            f"{both} are missed by BOTH (the model-hard residual)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
