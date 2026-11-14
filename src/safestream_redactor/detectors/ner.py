"""Tier 2: optional spaCy NER for PERSON / ORG / LOC entities.

spaCy is imported lazily so the core library stays dependency-free. Install
with ``pip install safestream-redactor[ner]`` plus a model, e.g.
``python -m spacy download en_core_web_sm``.
"""

from __future__ import annotations

import re
from typing import Any

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType

_LABEL_MAP = {
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORG,
    "GPE": EntityType.LOC,
    "LOC": EntityType.LOC,
    "FAC": EntityType.LOC,
}


def _load_model(model: str) -> Any:
    try:
        import spacy
    except ImportError as exc:
        raise ImportError(
            "spaCy is required for the NER tier. Install it with "
            "'pip install safestream-redactor[ner]' and download a model with "
            "'python -m spacy download en_core_web_sm'."
        ) from exc
    # only the NER component is needed; disabling the rest is much faster
    return spacy.load(model, exclude=["tagger", "parser", "lemmatizer", "attribute_ruler"])


# Prose mode (profile="prose"). A person's title belongs to the name it precedes
# ("Mr Eric Oldham"): spaCy leaves it out, which exposes it. Generic institution
# words that spaCy tags as organisations or places ("the Court", "Government")
# identify no one. Acronyms are kept: "PKK" or "IBM" can identify.
_TITLE = re.compile(
    r"(?:\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Sir|Dame|Lord|Lady|Judge|Justice|Rev)\.?\s+)$"
)
_TITLE_REACH = 16  # longest title plus spaces; within the declared left context
_GENERIC = frozenset(
    (
        "court", "courts", "government", "governments", "commission", "commissions",
        "chamber", "chambers", "grand chamber", "plenary court", "registrar", "registry",
        "state", "states", "parliament", "ministry", "ministries", "police", "council",
        "committee", "tribunal", "agency", "department", "office", "authority",
        "authorities", "board", "bureau", "section", "prosecutor", "prosecutors",
        "prosecution", "judge", "judges", "counsel", "delegate", "secretariat",
        "convention", "republic", "kingdom",
    )
)  # fmt: skip


def _generic(span: str) -> bool:
    words = span.split()
    if words and words[0].lower() in ("the", "a", "an"):
        words = words[1:]
    if not words:
        return True
    return " ".join(w.lower() for w in words) in _GENERIC


def _with_title(text: str, start: int, end: int) -> int:
    m = _TITLE.search(text, max(0, start - _TITLE_REACH), start)
    if m and end - m.start() <= NERDetector.requirements.max_span:
        return m.start()
    return start


class NERDetector:
    name = "ner"
    # Named entities are short, but the statistical model reads sentence context
    # on both sides, so declare a modest left/right context window. NER accuracy
    # can still degrade near a chunk boundary; that is a known limitation the
    # left/right context mitigates but does not eliminate (see docs/DETECTORS).
    requirements = StreamingRequirements(max_span=256, left_context=256, right_context=256)

    def __init__(
        self, model: str = "en_core_web_sm", confidence: float = 0.7, prose: bool = False
    ) -> None:
        self._model = model
        self._confidence = confidence
        self._prose = prose
        self._nlp = _load_model(model)

    # The loaded spaCy model is large and slow (sometimes impossible) to pickle,
    # which matters because the multiprocessing scheduler ships detectors to
    # worker processes. Pickle only the config and have each worker reload the
    # model locally — cheaper over IPC and robust to model-pickling quirks.
    def __getstate__(self) -> dict[str, Any]:
        return {"model": self._model, "confidence": self._confidence, "prose": self._prose}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._model = state["model"]
        self._confidence = state["confidence"]
        self._prose = state.get("prose", False)
        self._nlp = _load_model(self._model)

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for ent in self._nlp(text).ents:
            entity_type = _LABEL_MAP.get(ent.label_)
            if entity_type is None:
                continue
            start, end = ent.start_char, ent.end_char
            if self._prose:
                if entity_type is not EntityType.PERSON and _generic(ent.text):
                    continue
                if entity_type is EntityType.PERSON:
                    start = _with_title(text, start, end)
            found.append(
                Detection(
                    start=start,
                    end=end,
                    text=text[start:end],
                    entity_type=entity_type,
                    confidence=self._confidence,
                    source=self.name,
                    meta={"spacy_label": ent.label_},
                )
            )
        return found
