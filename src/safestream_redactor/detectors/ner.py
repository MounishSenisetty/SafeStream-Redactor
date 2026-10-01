"""Tier 2: spaCy NER for PERSON / ORG / LOC entities (on by default).

spaCy is a required dependency and this tier runs whenever a name type is in
scope. The statistical model itself is not on PyPI, so it is installed
separately with ``python -m spacy download en_core_web_sm``. When the model
cannot be loaded the redactor fails closed with :class:`NERUnavailableError`
rather than silently running without name coverage.
"""

from __future__ import annotations

from itertools import pairwise
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


class NERUnavailableError(ImportError):
    """spaCy or its model could not be loaded, so the NER tier cannot run.

    Raised instead of skipping the tier: a redactor that silently lost its
    PERSON/ORG/LOC coverage would leak names while reporting success.
    """


# Loaded pipelines, keyed by (spaCy module identity, model name). Loading a model
# takes ~0.5 s and ~100 MB, and every Redactor now carries this tier, so each
# process loads a given model once. The pipeline is only ever read (called on
# text), never mutated, so sharing it between redactors is safe.
_MODELS: dict[tuple[int, str], Any] = {}


def _load_model(model: str) -> Any:
    try:
        import spacy
    except ImportError as exc:
        raise NERUnavailableError(
            "spaCy is required for the NER tier. Install it with "
            "'pip install safestream-redactor[ner]' and download a model with "
            "'python -m spacy download en_core_web_sm'."
        ) from exc
    key = (id(spacy), model)
    nlp = _MODELS.get(key)
    if nlp is None:
        try:
            # only the NER component is needed; disabling the rest is much faster
            nlp = spacy.load(model, exclude=["tagger", "parser", "lemmatizer", "attribute_ruler"])
        except OSError as exc:
            raise NERUnavailableError(
                f"the spaCy model {model!r} is not installed, and the NER tier "
                "(PERSON/ORG/LOC) is on by default. Install it with "
                f"'python -m spacy download {model}', or turn the tier off "
                "explicitly (--no-ner / use_ner=False) to accept no name coverage."
            ) from exc
        _MODELS[key] = nlp
    return nlp


# Longest entity span emitted, and the context read on each side of a piece.
_MAX_SPAN = 256
_CONTEXT = 256
# spaCy refuses texts over ``nlp.max_length`` (1,000,000 chars by default) and its
# memory grows with input length, so text is fed to the model in pieces of about
# this many characters, each padded with _CONTEXT characters of real text.
_PIECE = 20_000


def _cut_points(text: str) -> list[int]:
    """Piece boundaries, preferring a newline, then a space, near each _PIECE mark."""
    cuts = [0]
    while len(text) - cuts[-1] > _PIECE:
        hard = cuts[-1] + _PIECE
        floor = hard - _PIECE // 10
        cut = text.rfind("\n", floor, hard)
        if cut == -1:
            cut = text.rfind(" ", floor, hard)
        cuts.append(cut + 1 if cut != -1 else hard)
    cuts.append(len(text))
    return cuts


class NERDetector:
    name = "ner"
    # Named entities are short, but the statistical model reads sentence context
    # on both sides, so declare a modest left/right context window. NER accuracy
    # can still degrade near a chunk boundary; that is a known limitation the
    # left/right context mitigates but does not eliminate (see docs/DETECTORS).
    # Longer entities are split into consecutive _MAX_SPAN pieces (see detect).
    requirements = StreamingRequirements(
        max_span=_MAX_SPAN, left_context=_CONTEXT, right_context=_CONTEXT
    )

    def __init__(self, model: str = "en_core_web_sm", confidence: float = 0.7) -> None:
        self._model = model
        self._confidence = confidence
        self._nlp = _load_model(model)

    # The loaded spaCy model is large and slow (sometimes impossible) to pickle,
    # which matters because the multiprocessing scheduler ships detectors to
    # worker processes. Pickle only the config and have each worker reload the
    # model locally — cheaper over IPC and robust to model-pickling quirks.
    def __getstate__(self) -> dict[str, Any]:
        return {"model": self._model, "confidence": self._confidence}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self._model = state["model"]
        self._confidence = state["confidence"]
        self._nlp = _load_model(self._model)

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        cuts = _cut_points(text)
        for own_start, own_end in pairwise(cuts):
            # each piece owns [own_start, own_end) and is read with real context
            # on both sides; an entity belongs to the piece its start falls in,
            # so one straddling a cut is reported exactly once
            lo = max(0, own_start - _CONTEXT)
            hi = min(len(text), own_end + _CONTEXT)
            for ent in self._nlp(text[lo:hi]).ents:
                entity_type = _LABEL_MAP.get(ent.label_)
                start = lo + ent.start_char
                if entity_type is None or not own_start <= start < own_end:
                    continue
                end = lo + ent.end_char
                # keep the declared max_span (the streaming overlap is sized from
                # it) without losing coverage: an over-long entity is reported as
                # consecutive spans that together cover all of it
                for s in range(start, end, _MAX_SPAN):
                    e = min(s + _MAX_SPAN, end)
                    found.append(
                        Detection(
                            start=s,
                            end=e,
                            text=text[s:e],
                            entity_type=entity_type,
                            confidence=self._confidence,
                            source=self.name,
                            meta={"spacy_label": ent.label_},
                        )
                    )
        return found
