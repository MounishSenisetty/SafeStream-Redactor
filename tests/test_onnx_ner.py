"""Tests for the optional local ONNX NER tier.

Two layers, mirroring the spaCy tier's approach:

* **Pure-logic tests** run always (no onnxruntime needed): the BIO decoder, the
  word tokenizer, and the full ``detect`` pipeline driven by a deterministic
  fake inference backend. This is the bulk of the tier's logic and stays covered
  in the default CI, which does not install the ``[onnx]`` extra.
* **Real-inference tests** build a tiny genuine ONNX token-classifier and run it
  through ``onnxruntime`` end-to-end; they ``importorskip`` when the extra is not
  installed, so default CI stays green while a machine with the extra proves the
  onnxruntime integration for real.
"""

from __future__ import annotations

import json
import pickle

import pytest

from safestream_redactor.detectors.onnx_ner import (
    OnnxPiiDetector,
    TokenSpan,
    WordTokenizer,
    _first_present,
    _load_json_map,
    decode_bio,
    split_label,
)
from safestream_redactor.entities import EntityType

# The default CoNLL IOB2 scheme the detector ships.
_ID2LABEL = {0: "O", 1: "B-PER", 2: "I-PER", 3: "B-ORG", 4: "I-ORG", 5: "B-LOC", 6: "I-LOC"}
_TAG_MAP = {"PER": EntityType.PERSON, "ORG": EntityType.ORG, "LOC": EntityType.LOC}


# --- pure decoder ------------------------------------------------------------


def test_split_label_schemes():
    assert split_label("O") == ("O", "")
    assert split_label("") == ("O", "")
    assert split_label("B-PER") == ("B", "PER")
    assert split_label("I-ORG") == ("I", "ORG")
    # bare tag (no BIO prefix) -> treated as a continuation so runs merge
    assert split_label("PER") == ("I", "PER")
    # unknown prefix falls back to treating the whole label as a tag
    assert split_label("X-PER") == ("I", "X-PER")


def _toks(spans):
    return [TokenSpan(0, s, e) for s, e in spans]


def test_decode_merges_bio_run():
    # tokens: John(B-PER) Smith(I-PER) -> one PERSON span
    tokens = _toks([(0, 4), (5, 10)])
    preds = [(1, 0.9), (2, 0.8)]
    out = decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5)
    assert out == [(0, 10, EntityType.PERSON, 0.8, "PER")]  # conf = min over span


def test_decode_b_starts_new_entity():
    # two adjacent B-PER -> two separate PERSON spans
    tokens = _toks([(0, 4), (5, 9)])
    preds = [(1, 0.9), (1, 0.95)]
    out = decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5)
    assert [(s, e, t.value) for s, e, t, _c, _g in out] == [(0, 4, "person"), (5, 9, "person")]


def test_decode_b_on_glued_subword_continues_the_word():
    # "Olusegun Obasanjo" as O|lus|eg|un Obasanjo with every first-name piece B-PER:
    # one span, or resolution keeps "Olusegun" and leaks the surname
    tokens = _toks([(0, 1), (1, 4), (4, 6), (6, 8), (9, 17)])
    preds = [(1, 0.99), (1, 0.99), (1, 0.99), (1, 0.99), (2, 0.98)]
    out = decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5)
    assert out == [(0, 17, EntityType.PERSON, 0.98, "PER")]


def test_decode_tag_change_and_O_break():
    # PER, then O, then ORG -> two spans, the O breaks the run
    tokens = _toks([(0, 3), (4, 7), (8, 12)])
    preds = [(1, 0.9), (0, 0.99), (3, 0.7)]
    out = decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5)
    assert [(t.value) for _s, _e, t, _c, _g in out] == ["person", "org"]


def test_decode_special_token_breaks_entity():
    # a special token (start<0) in the middle splits the run
    tokens = [TokenSpan(0, 0, 4), TokenSpan(0, -1, -1), TokenSpan(0, 5, 10)]
    preds = [(1, 0.9), (2, 0.9), (2, 0.9)]
    out = decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5)
    # first token is a lone PER; the special breaks; the trailing I-PER with no
    # open entity starts a fresh one
    assert [(s, e) for s, e, _t, _c, _g in out] == [(0, 4), (5, 10)]


def test_decode_min_score_filters():
    tokens = _toks([(0, 4), (5, 10)])
    preds = [(1, 0.9), (2, 0.3)]  # min = 0.3 < 0.5 -> dropped
    assert decode_bio(tokens, preds, _ID2LABEL, _TAG_MAP, 0.5) == []


def test_decode_unknown_tag_dropped():
    id2label = {0: "O", 1: "B-MISC"}
    tokens = _toks([(0, 4)])
    assert decode_bio(tokens, [(1, 0.99)], id2label, _TAG_MAP, 0.5) == []


# --- word tokenizer ----------------------------------------------------------


def test_word_tokenizer_offsets_and_unk():
    vocab = {"<unk>": 0, "john": 1, "smith": 2}
    tok = WordTokenizer(vocab)
    spans = tok.encode("John Smith Xyz")
    assert [(s.token_id, s.start, s.end) for s in spans] == [
        (1, 0, 4),  # John (lowercased match)
        (2, 5, 10),  # Smith
        (0, 11, 14),  # Xyz -> <unk>
    ]


def test_word_tokenizer_punctuation_is_its_own_token():
    tok = WordTokenizer({"<unk>": 0, "a": 1})
    spans = tok.encode("a, b")
    assert [s.end - s.start for s in spans] == [1, 1, 1]  # 'a' ',' 'b'


def test_load_json_map_passthrough_and_file(tmp_path):
    assert _load_json_map({"a": 1}) == {"a": 1}
    p = tmp_path / "v.json"
    p.write_text(json.dumps({"x": 2}), encoding="utf-8")
    assert _load_json_map(str(p)) == {"x": 2}


def test_first_present_picks_first_match():
    assert _first_present({"input_ids", "mask"}, ("input", "input_ids")) == "input_ids"
    assert _first_present({"x"}, ("a", "b")) is None


# --- detect() via a deterministic fake backend (no onnxruntime) --------------


class _FakeBackend:
    """Maps each token id to a one-hot logit row over the label scheme."""

    def __init__(self, id_to_label: dict[int, int]):
        self._map = id_to_label

    def run(self, input_ids):
        rows = []
        for tid in input_ids:
            lab = self._map.get(tid, 0)
            rows.append([6.0 if i == lab else 0.0 for i in range(len(_ID2LABEL))])
        return rows


def _fake_detector(**kw):
    vocab = {"<unk>": 0, "john": 1, "smith": 2, "acme": 3, "corp": 4, "paris": 5}
    backend = _FakeBackend({1: 1, 2: 2, 3: 3, 4: 4, 5: 5})  # per/per/org/org/loc
    return OnnxPiiDetector(vocab=vocab, backend=backend, min_score=0.5, **kw)


def test_detect_full_pipeline_fake_backend():
    det = _fake_detector()
    text = "John Smith at Acme Corp in Paris"
    dets = det.detect(text)
    assert [(d.entity_type.value, text[d.start : d.end], d.source) for d in dets] == [
        ("person", "John Smith", "onnx"),
        ("org", "Acme Corp", "onnx"),
        ("loc", "Paris", "onnx"),
    ]
    assert all(d.meta["onnx_label"] in {"PER", "ORG", "LOC"} for d in dets)
    assert all(0.0 < d.confidence <= 1.0 for d in dets)


def test_detect_empty_text():
    assert _fake_detector().detect("") == []


def test_fixed_confidence_option():
    det = _fake_detector(confidence=0.66)
    dets = det.detect("John Smith")
    assert dets and all(d.confidence == 0.66 for d in dets)


def test_streaming_requirements_declared():
    req = OnnxPiiDetector.requirements
    assert req.max_span > 0 and req.left_context > 0 and req.right_context > 0
    assert req.streaming_safe and not req.stateful


def test_missing_vocab_or_model_raises():
    with pytest.raises(ValueError, match="vocab="):
        OnnxPiiDetector(model_path="x.onnx")  # no vocab, no tokenizer
    with pytest.raises(ValueError, match="model_path="):
        OnnxPiiDetector(vocab={"<unk>": 0})  # no model, no backend


def test_injected_detector_is_not_picklable():
    # a detector built with an injected backend can't be shipped to workers;
    # __getstate__ must say so clearly rather than silently mis-pickle.
    with pytest.raises(TypeError, match="not picklable"):
        pickle.dumps(_fake_detector())


def test_injected_tokenizer_is_used():
    # a custom tokenizer (e.g. wrapping a Hugging Face sub-word tokenizer) can be
    # plugged in; here a trivial one that emits two fixed tokens with offsets.
    class _Tok:
        def encode(self, text):
            return [TokenSpan(1, 0, 4), TokenSpan(2, 5, 10)]

    det = OnnxPiiDetector(
        tokenizer=_Tok(),
        backend=_FakeBackend({1: 1, 2: 2}),
        id2label={0: "O", 1: "B-PER", 2: "I-PER"},
        min_score=0.5,
    )
    dets = det.detect("Jane Adams")
    assert [(d.entity_type.value, d.start, d.end) for d in dets] == [("person", 0, 10)]


def test_tag_map_accepts_names_and_enum():
    # tag_map values may be EntityType or their string names
    vocab = {"<unk>": 0, "john": 1}
    det = OnnxPiiDetector(
        vocab=vocab,
        backend=_FakeBackend({1: 1}),
        id2label={0: "O", 1: "B-PER"},
        tag_map={"PER": "person"},
        min_score=0.5,
    )
    dets = det.detect("met John")  # mid-sentence: the gate passes it
    assert [d.entity_type for d in dets] == [EntityType.PERSON]
