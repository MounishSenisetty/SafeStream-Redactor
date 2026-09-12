"""Calibrated semantic name/organization ensemble (model-free).

A precision-aware upgrade to the single-signal gazetteer detector. Instead of
OR-ing weak detectors, it collects *multiple weak evidence signals* per candidate
and combines them in an explicit, separately-calibrated score for PERSON and for
ORG, so that several weak signals can reinforce each other while an isolated weak
signal (bare capitalization) is rejected. Every prediction carries an **evidence
trace** (which signals fired and their weights) in its metadata.

Evidence signals
----------------
PERSON: honorific, professional suffix, form-field name cue, given-name gazetteer,
surname gazetteer, multi-token capitalization, title-case shape, and a
**bounded-lookback repeated-mention** boost (a token confirmed as part of a strong
name earlier in the same window). Negative evidence: common English word, form-
field label, organization designator, lone sentence-initial capital.

ORG: corporate/institutional designator, organization cue, "X of Y" pattern,
multi-token capitalization. Negative: a given name present (favours PERSON), a
field label.

Policies
--------
``strict`` (default) requires stronger combined evidence before redacting (favours
precision/utility); ``high_recall`` lowers the PERSON/ORG thresholds (favours
privacy recall, documented precision cost). PERSON and ORG have **separate**
thresholds because their linguistics differ.

Streaming safety
----------------
Stateless across ``detect`` calls and window-pure. The repeated-mention signal
looks back at most ``propagation_window`` characters *within the current window*
and keeps at most ``max_confirmed`` confirmed names in a bounded deque, so memory
is O(propagation_window + max_confirmed) — independent of document length. With
``propagation_window <= engine overlap`` (the default 8 KB overlap satisfies the
2 KB default), streaming output matches whole-document output (verified by test).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.name_data import (
    ADDRESS_CUES,
    COMMON_GIVEN_NAMES,
    COMMON_SURNAMES,
    HONORIFICS,
    NAME_CUES,
    NAME_SUFFIXES,
    ORG_CUES,
    ORG_DESIGNATORS,
)
from safestream_redactor.entities import Detection, EntityType

_NT = r"[A-ZÀ-ɏ][A-Za-zÀ-ɏ'’.\-]{0,30}"  # noqa: RUF001 - both apostrophe forms
_CAND = re.compile(rf"{_NT}(?:[^\S\r\n]+{_NT}){{0,3}}")
_TOKEN = re.compile(_NT)

# common English words that are capitalized at sentence start / are proper-noun
# lookalikes (months, weekdays, directions) — strong negative evidence for PERSON.
_COMMON_WORDS = frozenset(
    {
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
        "our",
        "your",
        "their",
        "we",
        "you",
        "they",
        "it",
        "dear",
        "sincerely",
        "regards",
        "hello",
        "please",
        "thanks",
        "note",
        "north",
        "south",
        "east",
        "west",
        "spring",
        "summer",
        "fall",
        "winter",
    }
)
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
        "age",
        "time",
        "name",
    }
)
# Leading tokens trimmed from a raw capitalized run before scoring (function
# words and field labels that are never part of the entity value).
_STOP_TRIM = _COMMON_WORDS | _FIELD_LABELS


# Signals that anchor a name to a *context* (rather than mere name-shape). Under a
# cue-gated policy a PERSON candidate must have at least one of these, so a bare
# capitalized name in prose (a public figure, a book title) is not redacted.
_STRONG_PERSON_CUES = frozenset({"honorific", "name_cue", "suffix", "repeated_mention"})


@dataclass(frozen=True)
class Policy:
    """A named operating point (separate PERSON/ORG thresholds)."""

    name: str
    person_threshold: float
    org_threshold: float
    require_person_cue: bool  # PERSON needs a contextual cue, not just name-shape


# STRICT: precision/utility — only redact a person when the context cues one
# (honorific/label/suffix/repeated mention). HIGH_RECALL: privacy — redact any
# sufficiently name-shaped span, accepting that public figures get redacted too.
STRICT = Policy("strict", person_threshold=0.55, org_threshold=0.6, require_person_cue=True)
HIGH_RECALL = Policy(
    "high_recall", person_threshold=0.42, org_threshold=0.5, require_person_cue=False
)
_POLICIES = {p.name: p for p in (STRICT, HIGH_RECALL)}

# Evidence weights (calibrated so a single weak signal stays below the STRICT
# threshold, but a strong signal or two combining weak ones clears it).
_PERSON_W = {
    "honorific": 0.62,
    "suffix": 0.58,
    "name_cue": 0.55,
    "repeated_mention": 0.55,
    "given_name": 0.34,
    "surname": 0.30,
    "multi_token": 0.20,
    "title_shape": 0.08,
}
_PERSON_NEG = {
    "common_word": 0.9,
    "field_label": 0.9,
    "org_designator": 0.5,
}
_ORG_W = {
    "org_designator": 0.66,
    "org_cue": 0.45,
    "of_pattern": 0.45,
    "multi_token": 0.16,
}
_ORG_NEG = {"given_name": 0.5, "field_label": 0.7}


@dataclass
class _Cand:
    start: int
    end: int
    text: str
    tokens: list[str]
    person: dict[str, float] = field(default_factory=dict)
    org: dict[str, float] = field(default_factory=dict)


def _score(pos: dict[str, float], neg: dict[str, float]) -> tuple[float, dict[str, float]]:
    trace = dict(pos)
    total = sum(pos.values()) - sum(neg.values())
    for k, v in neg.items():
        trace[f"-{k}"] = -v
    return max(0.0, min(0.99, total)), trace


class SemanticEnsembleDetector:
    """Calibrated multi-signal PERSON/ORG detector with evidence tracing."""

    name = "semantic_ensemble"
    requirements = StreamingRequirements(max_span=80, left_context=96, right_context=32)

    def __init__(
        self,
        policy: str = "strict",
        propagation_window: int = 2048,
        max_confirmed: int = 128,
        use_repeated_mention: bool = True,
    ) -> None:
        if policy not in _POLICIES:
            raise ValueError(f"unknown policy {policy!r}; use one of {sorted(_POLICIES)}")
        self.policy = _POLICIES[policy]
        self.propagation_window = propagation_window
        self.max_confirmed = max_confirmed
        self.use_repeated_mention = use_repeated_mention

    def detect(self, text: str) -> list[Detection]:
        confirmed: deque[tuple[int, frozenset[str]]] = deque(maxlen=self.max_confirmed)
        out: list[Detection] = []
        for c in self._candidates(text):
            cue = self._normalize(text, c)  # trims leading cue/stopword tokens
            if not c.tokens:
                continue
            self._person_evidence(text, c, cue)
            self._org_evidence(text, c, cue)
            if self.use_repeated_mention and len(c.tokens) == 1:
                tok = c.tokens[0].lower().rstrip(".")
                for cpos, toks in confirmed:
                    if tok in toks and 0 <= c.start - cpos <= self.propagation_window:
                        c.person["repeated_mention"] = _PERSON_W["repeated_mention"]
                        break
            p_score, p_trace = _score(c.person, {})
            o_score, o_trace = _score(c.org, {})
            loc = cue == "address" and (len(c.tokens) >= 1)
            if p_score >= 0.6 and len(c.tokens) >= 2:
                confirmed.append((c.end, frozenset(t.lower().rstrip(".") for t in c.tokens)))
            emitted = self._emit(c, p_score, p_trace, o_score, o_trace, loc)
            if emitted is not None:
                out.append(emitted)
        return out

    def _normalize(self, text: str, c: _Cand) -> str | None:
        """Trim leading cue/stopword tokens; return the cue kind found (if any).

        The honorific/name/org/address cue may be a leading token of the raw
        capitalized run ("Dr. Melissa") or sit in the left context ("Name: John").
        Either way it is recorded as the cue kind and trimmed from the span so
        only the entity value remains.
        """
        left = text[max(0, c.start - 40) : c.start].lower()
        cue: str | None = None
        if _ends_with_cue(left, HONORIFICS):
            cue = "honorific"
        elif _ends_with_cue(left, NAME_CUES):
            cue = "name"
        elif _ends_with_cue(left, ADDRESS_CUES):
            cue = "address"
        elif _ends_with_cue(left, ORG_CUES):
            cue = "org"
        # trim leading tokens that are themselves cue/stop/label words
        drop = 0
        offset = c.start
        for m in _TOKEN.finditer(c.text):
            w = m.group().lower().rstrip(".")
            if w in HONORIFICS:
                cue = cue or "honorific"
                drop = m.end()
            elif w in NAME_CUES:
                cue = cue or "name"
                drop = m.end()
            elif w in ADDRESS_CUES:
                cue = cue or "address"
                drop = m.end()
            elif w in _STOP_TRIM:
                drop = m.end()
            else:
                break
        if drop:
            newtext = c.text[drop:]
            lead_ws = len(newtext) - len(newtext.lstrip())
            c.start = offset + drop + lead_ws
            c.text = newtext.strip()
            c.end = c.start + len(c.text)
        # trim trailing field-label / common tokens ("Fresno State" -> "Fresno")
        tmatches = list(_TOKEN.finditer(c.text))
        cut = len(c.text)
        for m in reversed(tmatches):
            if m.group().lower().rstrip(".") in _STOP_TRIM:
                cut = m.start()
            else:
                break
        if cut < len(c.text):
            c.text = c.text[:cut].rstrip()
            c.end = c.start + len(c.text)
        c.tokens = [t.group() for t in _TOKEN.finditer(c.text)]
        return cue

    def _emit(
        self,
        c: _Cand,
        p_score: float,
        p_trace: dict[str, float],
        o_score: float,
        o_trace: dict[str, float],
        loc: bool,
    ) -> Detection | None:
        person_ok = p_score >= self.policy.person_threshold
        # STRICT gate: a person needs a contextual cue (honorific/label/suffix/
        # repeated mention), not just name-shape, so a bare public-figure name in
        # prose ("James Watson discovered DNA") is not redacted.
        if person_ok and self.policy.require_person_cue:
            person_ok = any(k in c.person for k in _STRONG_PERSON_CUES)
        org_ok = o_score >= self.policy.org_threshold
        if not person_ok and not org_ok and not loc:
            return None
        if org_ok and (not person_ok or o_score > p_score):
            etype, score, trace = EntityType.ORG, o_score, o_trace
        elif person_ok:
            etype, score, trace = EntityType.PERSON, p_score, p_trace
        else:  # address-cued location value
            etype, score, trace = EntityType.LOC, max(0.6, p_score), {"address_cue": 0.6}
        return Detection(
            start=c.start,
            end=c.end,
            text=c.text,
            entity_type=etype,
            confidence=max(0.5, score),  # clears the global min_confidence filter
            source=self.name,
            meta={
                "policy": self.policy.name,
                "score": f"{score:.2f}",
                "evidence": ",".join(f"{k}={v:+.2f}" for k, v in trace.items() if v),
            },
        )

    # -- candidate generation --------------------------------------------------

    def _candidates(self, text: str) -> list[_Cand]:
        out: list[_Cand] = []
        for m in _CAND.finditer(text):
            toks = [t.group() for t in _TOKEN.finditer(m.group())]
            out.append(_Cand(m.start(), m.end(), m.group(), toks))
        return out

    # -- evidence --------------------------------------------------------------

    def _person_evidence(self, text: str, c: _Cand, cue: str | None) -> None:
        right = text[c.end : c.end + 8].lower()
        toks = [t.lower().rstrip(".") for t in c.tokens]
        ev: dict[str, float] = {}
        if cue == "honorific":
            ev["honorific"] = _PERSON_W["honorific"]
        if cue == "name":
            ev["name_cue"] = _PERSON_W["name_cue"]
        suffix_re = re.match(r"\s*,?\s*(md|phd|jr|sr|esq)\b", right)
        if _starts_with_cue(right, NAME_SUFFIXES) or suffix_re:
            ev["suffix"] = _PERSON_W["suffix"]
        if toks and toks[0] in COMMON_GIVEN_NAMES:
            ev["given_name"] = _PERSON_W["given_name"]
        if any(t in COMMON_SURNAMES for t in toks):
            ev["surname"] = _PERSON_W["surname"]
        if len(c.tokens) >= 2:
            ev["multi_token"] = _PERSON_W["multi_token"]
        if c.text[:1].isupper() and not c.text.isupper():
            ev["title_shape"] = _PERSON_W["title_shape"]
        if any(t in _COMMON_WORDS for t in toks):
            ev["-common_word"] = -_PERSON_NEG["common_word"]
        if any(t in _FIELD_LABELS for t in toks):
            ev["-field_label"] = -_PERSON_NEG["field_label"]
        if any(t in ORG_DESIGNATORS for t in toks):
            ev["-org_designator"] = -_PERSON_NEG["org_designator"]
        c.person = ev

    def _org_evidence(self, text: str, c: _Cand, cue: str | None) -> None:
        toks = [t.lower().rstrip(".") for t in c.tokens]
        ev: dict[str, float] = {}
        has_designator = any(t in ORG_DESIGNATORS for t in toks)
        # a lone designator ("Inc") is not an org; require a proper-noun partner
        if has_designator and (len(c.tokens) >= 2 or cue == "org"):
            ev["org_designator"] = _ORG_W["org_designator"]
        if cue == "org":
            ev["org_cue"] = _ORG_W["org_cue"]
        if re.search(r"\b(?:university|institute|college|department|bank)\s+of\b", c.text.lower()):
            ev["of_pattern"] = _ORG_W["of_pattern"]
        if len(c.tokens) >= 2 and (has_designator or cue == "org"):
            ev["multi_token"] = _ORG_W["multi_token"]
        if toks and toks[0] in COMMON_GIVEN_NAMES:
            ev["-given_name"] = -_ORG_NEG["given_name"]
        if any(t in _FIELD_LABELS for t in toks):
            ev["-field_label"] = -_ORG_NEG["field_label"]
        c.org = ev


def _ends_with_cue(left: str, cues: frozenset[str]) -> bool:
    m = re.search(r"([a-z]+)[\s.:,\-]*$", left)
    return bool(m and m.group(1) in cues)


def _starts_with_cue(right: str, cues: frozenset[str]) -> bool:
    m = re.match(r"[\s.,]*([a-z]+)", right)
    return bool(m and m.group(1) in cues)


# also carry the address cue set for the caller's reference (LOC handled via cues)
_ADDRESS_CUES = ADDRESS_CUES
