"""Export a Hugging Face token-classification checkpoint to INT8 ONNX for the ONNX NER tier.

Writes four files into ``--out``:

* ``model.onnx``       fp32 export, dynamic batch and sequence axes
* ``model.int8.onnx``  the same graph with INT8 dynamic quantization (what you run)
* ``tokenizer.json``   the fast tokenizer (sub-word, with character offsets)
* ``labels.json``      id -> BIO tag

The default ``--out`` is the ONNX NER tier's discovery directory, so after exporting,
plain ``safestream redact`` and ``Redactor()`` auto-enable the tier with no flags:

    python scripts/export_onnx.py          # writes into ~/.cache/safestream-redactor/ner
    safestream redact in.txt -o out.txt    # tier auto-enabled from the exported model

Pass ``--out DIR`` to write elsewhere and point the tier at it with ``--onnx`` or the
``SAFESTREAM_ONNX_MODEL`` / ``_VOCAB`` / ``_LABELS`` environment variables.

Needs ``torch``, ``transformers``, ``onnx`` and ``onnxruntime`` (export-time only; the
redactor itself needs just the ``[onnx]`` extra plus ``tokenizers``). The default
checkpoint is a 66M-parameter DistilBERT fine-tuned on CoNLL-03 (PER/ORG/LOC/MISC).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from safestream_redactor.detectors.onnx_ner import default_model_dir

DEFAULT_MODEL = "dslim/distilbert-NER"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Hugging Face id or local path")
    ap.add_argument(
        "--out",
        default=default_model_dir(),
        type=Path,
        help="output directory (default: the tier's auto-discovery directory)",
    )
    ap.add_argument("--opset", default=17, type=int)
    ap.add_argument(
        "--archive",
        default=None,
        type=Path,
        metavar="PATH.tar.gz",
        help="also write a publishable .tar.gz of the exported files and print its SHA-256",
    )
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

    if args.archive is not None:
        from safestream_redactor.models import pack_model

        digest = pack_model(args.out, args.archive)
        # Machine-readable line the publish-model workflow greps for the digest to pin.
        print(f"MODEL_SHA256={digest}")
        print(f"archive: {args.archive}")


if __name__ == "__main__":
    main()
