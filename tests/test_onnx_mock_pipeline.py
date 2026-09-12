"""ONNX NER interface: end-to-end pipeline test with a DETERMINISTIC MOCK model.

This proves the local ONNX model contract (`detectors/onnx_ner.py`) integrates
with the real streaming Redactor — tokenization, inference, BIO decoding,
candidate reconciliation, and streaming/whole-document equivalence — WITHOUT a
downloaded model. The mock is a fixed, hand-built token classifier used ONLY for
interface/unit testing; it is not a real NER model and its "accuracy" is
meaningless. It never appears in any benchmark result.

To use a REAL local model instead, drop in an ONNX token-classifier via
`Redactor(use_onnx=True, onnx_model="model.onnx", onnx_vocab="vocab.json",
onnx_labels="id2label.json")` — see benchmarks/redactionbench/SEMANTIC_*.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from safestream_redactor import Redactor  # noqa: E402
from safestream_redactor.detectors.onnx_ner import (  # noqa: E402
    OnnxPiiDetector,
    TokenSpan,
)
from safestream_redactor.entities import EntityType  # noqa: E402

# A deterministic id->label scheme (CoNLL IOB2 subset) and a mock backend that
# tags any token whose text is in a fixed lexicon as B-PER/I-PER. This is the
# complete InferenceBackend contract: input_ids -> per-token logits.
_ID2LABEL = {0: "O", 1: "B-PER", 2: "I-PER"}
_PERSON_TOKENS = {"alice", "bob", "carol", "vance", "melissa"}


class _MockTokenizer:
    """text -> TokenSpans with character offsets (word-level, lowercased ids)."""

    import re as _re

    _WORD = _re.compile(r"\w+|[^\w\s]")

    def __init__(self) -> None:
        # ids are just hashes into a small space; the mock backend keys on text
        self._vocab: dict[str, int] = {}
        self.spans_text: dict[int, str] = {}

    def encode(self, text: str) -> list[TokenSpan]:
        out: list[TokenSpan] = []
        for m in self._WORD.finditer(text):
            w = m.group().lower()
            tid = self._vocab.setdefault(w, len(self._vocab) + 1)
            self.spans_text[tid] = w
            out.append(TokenSpan(tid, m.start(), m.end()))
        return out


class _MockBackend:
    """input_ids -> logits; tags known person tokens as B-PER, else O."""

    def __init__(self, tokenizer: _MockTokenizer) -> None:
        self._tok = tokenizer

    def run(self, input_ids: list[int]) -> list[list[float]]:
        rows: list[list[float]] = []
        for tid in input_ids:
            word = self._tok.spans_text.get(tid, "")
            if word in _PERSON_TOKENS:
                rows.append([0.0, 5.0, 0.0])  # strong B-PER
            else:
                rows.append([5.0, 0.0, 0.0])  # strong O
        return rows


def _mock_onnx_detector() -> OnnxPiiDetector:
    tok = _MockTokenizer()
    return OnnxPiiDetector(
        tokenizer=tok,
        backend=_MockBackend(tok),
        id2label=_ID2LABEL,
        min_score=0.5,
    )


def test_mock_onnx_detects_person() -> None:
    det = _mock_onnx_detector()
    dets = det.detect("Please contact Alice and Bob today.")
    names = {d.text for d in dets}
    assert "Alice" in names and "Bob" in names
    assert all(d.entity_type is EntityType.PERSON for d in dets)


def test_mock_onnx_integrates_with_redactor_pipeline() -> None:
    # inject the ONNX tier as an extra detector; the full pipeline (reconcile,
    # threshold, redact) must use it exactly like any other tier.
    r = Redactor(extra_detectors=[_mock_onnx_detector()])
    out = r.redact("Message Alice at bob@corp.io about the report.")
    assert "Alice" not in out  # caught by the ONNX tier
    assert "bob@corp.io" not in out  # caught by the deterministic tier
    assert "report" in out


def test_mock_onnx_streaming_equivalence() -> None:
    from benchmarks.redactionbench import adapter

    r = Redactor(extra_detectors=[_mock_onnx_detector()])
    text = "Alice met Bob and Carol. Vance emailed Melissa about it. " * 20
    key = lambda ps: sorted((p.start, p.end, p.label) for p in ps)  # noqa: E731
    for chunk in (8, 16, 32):
        assert key(adapter.predict_streaming(r, text, chunk)) == key(adapter.predict_whole(r, text))
