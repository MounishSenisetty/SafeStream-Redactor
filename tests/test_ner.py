"""NER tier tests using an injected fake spaCy (no real extra required).

The important property under test is that the detector pickles as config only
(model name + confidence) and reloads the model on unpickle, so the
multiprocessing scheduler can ship it to workers without serializing a large
model object.
"""

import pickle
import sys
import types

import pytest

from safestream_redactor.entities import EntityType


class _FakeEnt:
    def __init__(self, label, start, end, text):
        self.label_ = label
        self.start_char = start
        self.end_char = end
        self.text = text


class _FakeDoc:
    def __init__(self, ents):
        self.ents = ents


class _FakeNLP:
    def __call__(self, text):
        ents = []
        idx = text.find("Alice")
        if idx != -1:
            ents.append(_FakeEnt("PERSON", idx, idx + 5, "Alice"))
        return _FakeDoc(ents)


@pytest.fixture
def fake_spacy(monkeypatch):
    mod = types.ModuleType("spacy")
    mod.load = lambda name, exclude=None: _FakeNLP()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "spacy", mod)
    return mod


def _detector(model="fake-model"):
    from safestream_redactor.detectors.ner import NERDetector

    return NERDetector(model=model)


def test_ner_detects_via_model(fake_spacy):
    dets = _detector().detect("hello Alice here")
    assert len(dets) == 1
    assert dets[0].entity_type is EntityType.PERSON
    assert dets[0].text == "Alice"


def test_getstate_carries_config_not_the_model(fake_spacy):
    det = _detector()
    state = det.__getstate__()
    assert state == {"model": "fake-model", "confidence": 0.7}
    assert "_nlp" not in state  # the heavy model object is not serialized


def test_pickle_roundtrip_reloads_model(fake_spacy):
    det = _detector()
    restored = pickle.loads(pickle.dumps(det))
    assert restored._model == "fake-model"
    # the reloaded detector is fully functional
    assert restored.detect("ping Alice")[0].entity_type is EntityType.PERSON


def test_missing_spacy_raises_helpful_error(monkeypatch):
    # simulate the extra not being installed
    monkeypatch.setitem(sys.modules, "spacy", None)
    from safestream_redactor.detectors.ner import NERDetector

    with pytest.raises(ImportError, match=r"pip install safestream-redactor\[ner\]"):
        NERDetector()
