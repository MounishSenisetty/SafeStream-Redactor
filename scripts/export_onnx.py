"""Export a Hugging Face token-classification checkpoint to INT8 ONNX for the ONNX NER tier.

Writes four files into ``--out``:

* ``model.onnx``       fp32 export, dynamic batch and sequence axes
* ``model.int8.onnx``  the same graph with INT8 dynamic quantization (what you run)
* ``tokenizer.json``   the fast tokenizer (sub-word, with character offsets)
* ``labels.json``      id -> BIO tag

Then:

    safestream redact in.txt -o out.txt --onnx models/ner/model.int8.onnx \\
        --onnx-vocab models/ner/tokenizer.json --onnx-labels models/ner/labels.json

Needs ``torch``, ``transformers``, ``onnx`` and ``onnxruntime`` (export-time only; the
redactor itself needs just the ``[onnx]`` extra plus ``tokenizers``). The default
checkpoint is a 66M-parameter DistilBERT fine-tuned on CoNLL-03 (PER/ORG/LOC/MISC).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_MODEL = "dslim/distilbert-NER"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Hugging Face id or local path")
    ap.add_argument("--out", default="models/ner", type=Path)
    ap.add_argument("--opset", default=17, type=int)
    args = ap.parse_args()

    import onnx
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if not tokenizer.is_fast:
        raise SystemExit(f"{args.model} has no fast tokenizer (tokenizer.json); pick another")
    # eager attention: the fused SDPA kernels do not trace into a portable graph
    model = AutoModelForTokenClassification.from_pretrained(
        args.model, attn_implementation="eager"
    ).eval()

    args.out.mkdir(parents=True, exist_ok=True)
    fp32, int8 = args.out / "model.onnx", args.out / "model.int8.onnx"
    sample = dict(
        tokenizer(["Dr. Jane Doe met John Smith", "hi"], padding=True, return_tensors="pt")
    )
    axes = {name: {0: "batch", 1: "seq"} for name in [*sample, "logits"]}
    with torch.no_grad():
        torch.onnx.export(
            model,
            (),
            str(fp32),
            kwargs=sample,
            input_names=list(sample),
            output_names=["logits"],
            dynamic_axes=axes,
            opset_version=args.opset,
            dynamo=False,
        )
    # onnxruntime reads IR <= 10 everywhere the [onnx] extra allows; newer onnx
    # packages stamp a higher version than the opset needs
    graph = onnx.load(str(fp32))
    graph.ir_version = min(graph.ir_version, 10)
    onnx.save(graph, str(fp32))
    quantize_dynamic(str(fp32), str(int8), weight_type=QuantType.QInt8)

    tokenizer.backend_tokenizer.save(str(args.out / "tokenizer.json"))
    labels = {str(k): v for k, v in model.config.id2label.items()}
    (args.out / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
    for f in (fp32, int8):
        print(f"{f}  {f.stat().st_size / 1e6:.0f} MB")
    print(f"labels: {sorted(set(labels.values()))}")


if __name__ == "__main__":
    main()
