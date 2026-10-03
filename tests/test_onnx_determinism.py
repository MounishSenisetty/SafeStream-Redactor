"""ONNX tier output must not depend on how the text is chunked or split.

An INT8 dynamically quantized model computes one activation scale over its
whole input tensor, so a window's scores depend on which other windows share
its batch, and batch composition depends on chunking. The real exported model
changed ~10% of its spans between 16K and 24K chunks on a RedactionBench
document. The tiny model below reproduces that batch dependence exactly (the
"O" logit is shifted by the largest token id anywhere in the batch), so these
tests fail if batching ever becomes the default again.
"""

from __future__ import annotations

import json

import pytest

onnx = pytest.importorskip("onnx", reason="onnx not installed ([onnx] extra)")
pytest.importorskip("onnxruntime", reason="onnxruntime not installed ([onnx] extra)")
np = pytest.importorskip("numpy")

import safestream_redactor.parallel as par  # noqa: E402
from safestream_redactor import Redactor  # noqa: E402
from safestream_redactor.parallel import redact_file_parallel  # noqa: E402

_ID2LABEL = {0: "O", 1: "B-PER", 2: "I-PER", 3: "B-LOC"}
_WORDS = ["<unk>", "john", "smith", "in", "paris"] + [f"w{i}" for i in range(5, 20)] + ["zebra"]
_VOCAB = {w: i for i, w in enumerate(_WORDS)}
_TOKEN_LABEL = {_VOCAB["john"]: 1, _VOCAB["smith"]: 2, _VOCAB["paris"]: 3}


def _build_batch_dependent_model(path: str) -> None:
    """logits = W[input_ids] + onehot(O) * 0.5 * max(input_ids over the batch)."""
    from onnx import TensorProto, helper

    v, n = len(_VOCAB), len(_ID2LABEL)
    w = np.zeros((v, n), dtype=np.float32)
    for tid in range(v):
        w[tid, _TOKEN_LABEL.get(tid, 0)] = 6.0
    o_bias = np.zeros(n, dtype=np.float32)
    o_bias[0] = 0.5
    nodes = [
        helper.make_node("Gather", ["W", "input_ids"], ["g"], axis=0),
        helper.make_node("ReduceMax", ["input_ids"], ["m"], keepdims=0),  # whole batch
        helper.make_node("Cast", ["m"], ["mf"], to=TensorProto.FLOAT),
        helper.make_node("Mul", ["mf", "OB"], ["shift"]),
        helper.make_node("Add", ["g", "shift"], ["logits"]),
    ]
    graph = helper.make_graph(
        nodes,
        "batchdep",
        [helper.make_tensor_value_info("input_ids", TensorProto.INT64, [None, None])],
        [helper.make_tensor_value_info("logits", TensorProto.FLOAT, [None, None, n])],
        initializer=[
            helper.make_tensor("W", TensorProto.FLOAT, list(w.shape), w.flatten().tolist()),
            helper.make_tensor("OB", TensorProto.FLOAT, [n], o_bias.tolist()),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)], ir_version=10)
    onnx.checker.check_model(model)
    onnx.save(model, path)


@pytest.fixture
def model(tmp_path):
    path = tmp_path / "batchdep.onnx"
    _build_batch_dependent_model(str(path))
    vocab = tmp_path / "vocab.json"
    vocab.write_text(json.dumps(_VOCAB), encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({str(k): v for k, v in _ID2LABEL.items()}), encoding="utf-8")
    return str(path), str(vocab), str(labels)


def _text(lines: int = 300) -> str:
    # rare "Zebra" lines among name lines, with equal token counts so they share
    # batches (windows are batched by length): a Zebra window (token id 20)
    # pushes the O logit above every entity in its batch, its own included
    out = []
    for i in range(lines):
        out.append("John Smith in Zebra" if i % 40 == 0 else "John Smith in Paris")
        out.append("filler line " + "ok " * (i % 7))
    return "\n".join(out) + "\n"


def _redactor(model, chunk: int, **kw):
    path, vocab, labels = model
    return Redactor(
        use_onnx=True,
        onnx_model=path,
        onnx_vocab=vocab,
        onnx_labels=labels,
        min_confidence=0.0,
        use_entropy=False,
        load_plugins=False,
        chunk_size=chunk,
        overlap=1024,
        allow_unsafe_overlap=True,
        **kw,
    )


def _stream_spans(r: Redactor, text: str, step: int) -> list[tuple[int, int, str]]:
    out, off = [], 0
    for seg, dets in r.detect_stream(text[i : i + step] for i in range(0, len(text), step)):
        out += [(off + d.start, off + d.end, d.entity_type.value) for d in dets]
        off += len(seg)
    return sorted(out)


def test_batched_inference_is_chunking_dependent(model):
    """Sensitivity check: with batching opted in, the model really diverges."""
    text = _text()
    a = _stream_spans(_redactor(model, 1024, onnx_batch_size=32), text, 1024)
    b = _stream_spans(_redactor(model, 3000, onnx_batch_size=32), text, 3000)
    assert a != b


def test_default_inference_is_identical_across_chunk_sizes_and_whole_text(model):
    text = _text()
    runs = [_stream_spans(_redactor(model, c), text, c) for c in (1024, 1500, 3000, 8192)]
    whole = sorted(
        (d.start, d.end, d.entity_type.value) for d in _redactor(model, 1024).detect(text)
    )
    assert runs[0]  # names are found
    assert all(r == runs[0] for r in runs)
    assert whole == runs[0]


@pytest.mark.parametrize("workers", [2, 4])
def test_default_inference_parallel_equals_sequential(model, tmp_path, monkeypatch, workers):
    monkeypatch.setattr(par, "MIN_RANGE_BYTES", 4096)  # split this small file for real
    src = tmp_path / "in.txt"
    src.write_text(_text(600), encoding="utf-8")
    r = _redactor(model, 1024)
    r.redact_file(src, tmp_path / "seq.txt")
    outcome = redact_file_parallel(r, str(src), str(tmp_path / "par.txt"), workers=workers)
    assert outcome.ranges > 1 and not outcome.fell_back
    assert (tmp_path / "par.txt").read_bytes() == (tmp_path / "seq.txt").read_bytes()
    assert b"John Smith in Paris" not in (tmp_path / "seq.txt").read_bytes()
