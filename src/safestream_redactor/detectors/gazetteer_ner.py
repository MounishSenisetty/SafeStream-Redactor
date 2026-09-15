"""Lightweight, model-free semantic name/organization detector.

A supplementary semantic tier for the case where the neural NER tiers (spaCy /
ONNX) are not installed, and a complement to them when they are. It proposes
PERSON and ORG candidates from **precision-gated lexical signals** rather than a
statistical model:

* an **honorific** immediately before capitalized tokens (``Dr. Melissa Vance``);
* a **professional/generational suffix** after them (``Leona Qureshi, MD``);
* a **form-field cue** introducing them (``Patient Name: John Rivera``);
* a **common given name** from a small gazetteer followed by a capitalized token
  (``James Wilson``) — a deliberately *weak* signal;
* a **corporate designator** marking an organization (``Acme Systems, Inc``,
  ``University of Texas``).

Each signal carries a hand-set confidence reflecting its reliability, so the
engine's ``min_confidence`` threshold trades recall for precision across them
(the strong cue signals clear 0.7; the gazetteer/org signals sit near 0.55-0.6
and drop out first as the threshold rises). Only the **name span** is emitted,
never the cue word. It is stateless and window-pure with a small declared
context window, so it preserves the streaming/parallel equivalence guarantees.

This is intentionally not a replacement for a real NER model — a small gazetteer
trades precision for recall on ordinary prose, and non-Latin scripts (CJK, etc.)
need the neural tiers. It is a dependency-free floor and a high-precision
ensemble partner.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.name_data import (
    COMMON_GIVEN_NAMES,
    HONORIFICS,
    NAME_CUES,
    NAME_SUFFIXES,
    ORG_DESIGNATORS,
)
from safestream_redactor.entities import Detection, EntityType

# A single name token: starts uppercase (Latin incl. accented/extended), then
# name characters. Bounded length keeps a runaway match from crossing sentences.
# the class includes both apostrophe forms (U+0027 and U+2019), real name chars
_NT = r"[A-ZÀ-ɏ][A-Za-zÀ-ɏ'’.\-]{0,30}"  # noqa: RUF001
# 1..4 capitalized tokens on the SAME line — the separator is horizontal
# whitespace only (``[^\S\r\n]``), so a name never runs across a line break into
# the next form field (e.g. "Melissa\n\nAddress").
_NAME = rf"{_NT}(?:[^\S\r\n]+{_NT}){{0,3}}"

# Capitalized words that are not names/orgs (sentence-initial function words,
# salutation glue). Filtered from the head of a captured span to curb false
# positives like "The Systems team" or "Dear Sir".
_STOP_CAPS = frozenset(
    {
        "the",
        "this",
        "that",
        "these",
        "those",
        "a",
        "an",
        "and",
        "or",
        "but",
        "for",
        "with",
        "from",
        "to",
        "in",
        "on",
        "at",
        "of",
        "by",
        "as",
        "our",
        "your",
        "their",
        "his",
        "her",
        "its",
        "we",
        "you",
        "they",
        "it",
        "i",
        "dear",
        "sincerely",
        "regards",
        "thanks",
        "thank",
        "hello",
        "hi",
        "please",
        "attn",
        "re",
        "subject",
        "date",
        "sir",
        "madam",
        "mr",
        "mrs",
        "ms",
        "dr",
    }
)

_HON = "|".join(sorted(map(re.escape, HONORIFICS), key=len, reverse=True))
_SUF = "|".join(sorted(map(re.escape, NAME_SUFFIXES), key=len, reverse=True))
_CUE = "|".join(sorted(map(re.escape, NAME_CUES), key=len, reverse=True))
_ORG = "|".join(sorted(map(re.escape, ORG_DESIGNATORS), key=len, reverse=True))

# NOTE: only the keyword alternations are case-insensitive (scoped ``(?i:...)``);
# the NAME tokens stay case-sensitive so the "starts uppercase" constraint holds.
# A global re.IGNORECASE would make ``[A-Z...]`` match lowercase too and the name
# capture would run past its end into following lowercase words.
_RE_HONORIFIC = re.compile(rf"\b(?i:{_HON})\.?\s+({_NAME})")
_RE_SUFFIX = re.compile(rf"\b({_NAME})\s*,?\s+(?i:{_SUF})\b")
_RE_CUE = re.compile(rf"\b(?i:{_CUE})\b\s*[:\-]?\s+({_NAME})")
_RE_CAPSEQ = re.compile(rf"{_NT}(?:[^\S\r\n]+{_NT}){{1,3}}")  # ≥2 same-line capitalized tokens
_RE_ORG_TRAIL = re.compile(rf"\b({_NAME})[, ]+(?i:{_ORG})\b\.?")
_RE_ORG_LEAD = re.compile(rf"\b(?i:{_ORG})\s+of\s+({_NAME})")


# Capitalized words that are not part of a name and must be trimmed from either
# end of a captured span: function words, the cue/label words themselves (so
# "Patient Name: John" does not redact "Name"), and common form-field labels that
# sit adjacent to a value ("... Melissa Schettler   Date" -> drop "Date").
_FIELD_LABELS = frozenset(
    {
        "date",
        "address",
        "signed",
        "signature",
        "phone",
        "email",
        "fax",
        "city",
        "state",
        "zip",
        "zipcode",
        "country",
        "dob",
        "ssn",
        "id",
        "title",
        "subject",
        "from",
        "to",
        "re",
        "page",
        "total",
        "amount",
        "no",
        "number",
        "type",
        "status",
        "department",
        "position",
        "role",
        "gender",
        "sex",
        "age",
        "time",
        "recommendation",
        "comments",
        "notes",
        "reference",
        "account",
    }
)
_EDGE_STOP = _STOP_CAPS | NAME_CUES | _FIELD_LABELS


def _trim_stopwords(text: str, start: int, end: int) -> tuple[int, int]:
    """Trim leading and trailing capitalized function/label words from a span."""
    toks = list(re.finditer(_NT, text[start:end]))
    if not toks:
        return start, end
    lead = 0
    for m in toks:
        if m.group().lower().rstrip(".") in _EDGE_STOP:
            lead = m.end()
        else:
            break
    trail = len(text[start:end])
    for m in reversed(toks):
        if m.start() < lead:
            break
        if m.group().lower().rstrip(".") in _EDGE_STOP:
            trail = m.start()
        else:
            break
    return start + lead, start + trail


def _strip_trailing_punct(value: str) -> str:
    """Strip trailing sentence punctuation, keeping a genuine initial's period.

    ``Diane Luna.`` -> ``Diane Luna`` (period follows a lowercase letter, so it
    ends the sentence), but ``John A.`` keeps its period (it follows an
    uppercase initial). Also trims trailing ``, ; :`` and closing brackets.
    """
    v = value.rstrip(",;:)]}»\"'")
    if v.endswith(".") and len(v) >= 2 and v[-2].islower():
        v = v[:-1]
    return v.rstrip()


class GazetteerNameDetector:
    """Model-free PERSON/ORG detection from precision-gated lexical cues."""

    name = "gazetteer_name"
    # Emits a name span up to a few tokens; reads a short left window for the cue.
    requirements = StreamingRequirements(max_span=64, left_context=64, right_context=8)

    def __init__(
        self,
        honorific_conf: float = 0.85,
        suffix_conf: float = 0.8,
        cue_conf: float = 0.72,
        gazetteer_conf: float = 0.55,
        org_conf: float = 0.6,
        use_gazetteer: bool = True,
    ) -> None:
        self.honorific_conf = honorific_conf
        self.suffix_conf = suffix_conf
        self.cue_conf = cue_conf
        self.gazetteer_conf = gazetteer_conf
        self.org_conf = org_conf
        self.use_gazetteer = use_gazetteer

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []

        def emit(s: int, e: int, etype: EntityType, conf: float, signal: str) -> None:
            s, e = _trim_stopwords(text, s, e)
            raw = text[s:e]
            s += len(raw) - len(raw.lstrip())  # advance past any leading whitespace
            value = _strip_trailing_punct(raw.strip())
            if len(value) < 2:
                return
            # must contain a proper-noun (uppercase-initial) token — guards against
            # a bare designator like "committee" surviving after the name is trimmed.
            if not re.search(r"[A-ZÀ-ɏ]", value):
                return
            found.append(
                Detection(
                    start=s,
                    end=s + len(value),
                    text=value,
                    entity_type=etype,
                    confidence=conf,
                    source=self.name,
                    meta={"signal": signal, "norm": _normalize(value)},
                )
            )

        for m in _RE_HONORIFIC.finditer(text):
            emit(m.start(1), m.end(1), EntityType.PERSON, self.honorific_conf, "honorific")
        for m in _RE_SUFFIX.finditer(text):
            emit(m.start(1), m.end(1), EntityType.PERSON, self.suffix_conf, "suffix")
        for m in _RE_CUE.finditer(text):
            emit(m.start(1), m.end(1), EntityType.PERSON, self.cue_conf, "cue")
        for m in _RE_ORG_TRAIL.finditer(text):
            emit(m.start(1), m.end(0), EntityType.ORG, self.org_conf, "org_designator")
        for m in _RE_ORG_LEAD.finditer(text):
            emit(m.start(0), m.end(0), EntityType.ORG, self.org_conf, "org_designator")

        if self.use_gazetteer:
            for m in _RE_CAPSEQ.finditer(text):
                toks = list(re.finditer(_NT, m.group()))
                if not toks:
                    continue
                first = toks[0].group().lower().rstrip(".")
                if first in COMMON_GIVEN_NAMES:
                    emit(m.start(), m.end(), EntityType.PERSON, self.gazetteer_conf, "gazetteer")

        return found


def _normalize(value: str) -> str:
    """A normalized form of a name span (whitespace/case), for candidate records.

    Kept separate from the emitted span, whose offsets always point back to the
    original text so redaction covers the exact original characters.
    """
    return re.sub(r"\s+", " ", value).strip().casefold()
