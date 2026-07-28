"""Tier 2: optional spaCy NER for PERSON / ORG / LOC entities.

spaCy is imported lazily so the core library stays dependency-free. Install
with ``pip install safestream-redactor[ner]`` plus a model, e.g.
``python -m spacy download en_core_web_sm``.
"""

from __future__ import annotations

from typing import Any

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


class NERDetector:
    name = "ner"

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
        for ent in self._nlp(text).ents:
            entity_type = _LABEL_MAP.get(ent.label_)
            if entity_type is None:
                continue
            found.append(
                Detection(
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    entity_type=entity_type,
                    confidence=self._confidence,
                    source=self.name,
                    meta={"spacy_label": ent.label_},
                )
            )
        return found
