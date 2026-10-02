"""Real ONNX inference tests for the local ONNX NER tier.

These build a tiny genuine ONNX token-classifier and run it through
``onnxruntime`` end-to-end, so the onnxruntime integration (session load, feed,
run, logits) is exercised for real — not faked. The whole module is skipped when
the ``[onnx]`` extra is not installed, so the default CI (which does not install
it) stays green; a machine with the extra proves the integration. The tier's
pure logic (decoder, tokenizer, decode pipeline) is covered without any extra in
``tests/test_onnx_ner.py``.
"""

from __future__ import annotations

import json
import pickle

import pytest

onnx = pytest.importorskip("onnx", reason="onnx not installed ([onnx] extra)")
ort = pytest.importorskip("onnxruntime", reason="onnxruntime not installed ([onnx] extra)")
np = pytest.importorskip("numpy")

# imports after importorskip so the module skips cleanly without the extra
from safestream_redactor.detectors.onnx_ner import OnnxPiiDetector  # noqa: E402

_ID2LABEL = {0: "O", 1: "B-PER", 2: "I-PER", 3: "B-ORG", 4: "I-ORG", 5: "B-LOC", 6: "I-LOC"}
_VOCAB = {
    "<unk>": 0, "john": 1, "smith": 2, "works": 3, "at": 4,
    "acme": 5, "corp": 6, "in": 7, "paris": 8,
}  # fmt: skip
_TOKEN_LABEL = {1: 1, 2: 2, 5: 3, 6: 4, 8: 5}  # john/smith=PER acme/corp=ORG paris=LOC


def _build_tiny_model(path: str) -> None:
    """A real word-level classifier: logits = Gather(W, input_ids)."""
    from onnx import TensorProto, helper

    v, num_labels = len(_VOCAB), len(_ID2LABEL)
    weights = np.zeros((v, num_labels), dtype=np.float32)
    for tid in range(v):
        weights[tid, _TOKEN_LABEL.get(tid, 0)] = 6.0
    init = helper.make_tensor(
        "W", TensorProto.FLOAT, list(weights.shape), weights.flatten().tolist()
    )
    node = helper.make_node("Gather", inputs=["W", "input_ids"], outputs=["logits"], axis=0)
    graph = helper.make_graph(
        [node],
        "wordcls",
        [helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, None])],
        [helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, None, num_labels])],
        initializer=[init],
    )
    # IR 10: readable by every onnxruntime the [onnx] extra allows, whatever onnx wrote it
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)], ir_version=10)
    onnx.checker.check_model(model)
    onnx.save(model, path)


@pytest.fixture
def tiny_model(tmp_path):
    path = str(tmp_path / "tiny.onnx")
    _build_tiny_model(path)
    (tmp_path / "vocab.json").write_text(json.dumps(_VOCAB), encoding="utf-8")
    return path, str(tmp_path / "vocab.json")


def test_real_onnxruntime_inference(tiny_model):
    model_path, vocab_path = tiny_model
    det = OnnxPiiDetector.from_files(model_path, vocab_path, min_score=0.5)
    text = "John Smith works at Acme Corp in Paris"
    dets = det.detect(text)
    assert [(d.entity_type.value, text[d.start : d.end]) for d in dets] == [
        ("person", "John Smith"),
        ("org", "Acme Corp"),
        ("loc", "Paris"),
    ]


def test_real_detector_pickles_and_reloads(tiny_model):
    # file-based detector must survive pickling (the parallel scheduler ships it)
    model_path, vocab_path = tiny_model
    det = OnnxPiiDetector.from_files(model_path, vocab_path, min_score=0.5)
    restored = pickle.loads(pickle.dumps(det))
    assert [d.entity_type.value for d in restored.detect("John Smith in Paris")] == [
        "person",
        "loc",
    ]


def test_real_from_files_with_explicit_labels(tiny_model, tmp_path):
    model_path, vocab_path = tiny_model
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps({str(k): v for k, v in _ID2LABEL.items()}), encoding="utf-8")
    det = OnnxPiiDetector.from_files(model_path, vocab_path, str(labels_path), min_score=0.5)
    assert [d.entity_type.value for d in det.detect("in Paris")] == ["loc"]


def test_redactor_integration_use_onnx(tiny_model):
    from safestream_redactor import Redactor

    model_path, vocab_path = tiny_model
    r = Redactor(use_onnx=True, onnx_model=model_path, onnx_vocab=vocab_path, min_confidence=0.0)
    assert "onnx" in r.detector_names
    assert r.redact("John Smith works at Acme Corp in Paris") == (
        "[REDACTED] works at [REDACTED] in [REDACTED]"
    )


def test_cli_redact_with_onnx(tiny_model, tmp_path, capsys):
    from safestream_redactor.cli import main

    model_path, vocab_path = tiny_model
    inp = tmp_path / "in.txt"
    # bytes, not write_text: on Windows that writes "\r\n", which the redactor
    # (correctly) preserves in its output
    inp.write_bytes(b"John Smith works at Acme Corp in Paris\n")
    argv = ["redact", str(inp), "-o", "-", "--onnx", model_path]
    argv += ["--onnx-vocab", vocab_path, "--min-confidence", "0.0"]
    rc = main(argv)
    assert rc == 0
    assert capsys.readouterr().out == "[REDACTED] works at [REDACTED] in [REDACTED]\n"


def test_onnx_detect_makes_no_network_calls(tiny_model):
    # local-first guarantee: run detect() under the offline network guard and
    # confirm it still works (the guard raises on any non-loopback connection).
    from safestream_redactor import netguard

    model_path, vocab_path = tiny_model
    det = OnnxPiiDetector.from_files(model_path, vocab_path, min_score=0.5)
    netguard.install()
    try:
        dets = det.detect("John Smith in Paris")
    finally:
        netguard.uninstall()
    assert [d.entity_type.value for d in dets] == ["person", "loc"]
