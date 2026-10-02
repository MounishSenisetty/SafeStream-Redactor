# Detectors

SafeStream uses a four-tier detector cascade. Every detection is a
`Detection` (`entities.py`) carrying a span, entity type, confidence, and source
tier; overlaps are resolved most-specific/highest-confidence wins.

## Tiers

| Tier | Module | What it does |
| --- | --- | --- |
| 1. Deterministic | `detectors/deterministic.py` | Anchored regexes + validators (Luhn, `ipaddress`, SSN rules). Highest precision. |
| 2. Statistical | `detectors/entropy.py` | High-entropy tokens with no published format (bespoke keys, session tokens). |
| 2b. Compound secret | `detectors/entropy.py` (`CompoundSecretDetector`) | High-entropy runs carrying an *embedded strong special* (`! # $ % ^ & * ~`) the base64 entropy candidate splits on — symbol-containing passwords/blobs. Precision-gated (embedded special + class diversity + entropy floor); emits `secret`. |
| 3. NER (optional) | `detectors/ner.py` | spaCy PERSON/ORG/LOC. Requires the `ner` extra + a model. |
| 3b. ONNX NER (optional) | `detectors/onnx_ner.py` | Local ONNX token-classifier for PERSON/ORG/LOC, on-device, no data egress. Requires the `onnx` extra + a model. |
| 4. Contextual | `detectors/contextual.py` | Nudges confidence from surrounding trigger words; promotes trigger-gated spans (bare SSN next to "ssn:"). |

Custom words/regexes (`detectors/custom.py`) and third-party plugins
(entry-point group `safestream_redactor.detectors`, loaded only when enabled with
`load_plugins=True` / `--enable-plugins` / `[plugins] enabled = true`) plug in
alongside these.

### The optional ONNX NER tier

An alternative to the spaCy tier that runs a local ONNX token-classification
model (BIO/IOB2 tagging) entirely on-device via `onnxruntime` — **no network, no
data egress** (CPU execution provider only; a test runs it under the offline
network guard). It targets the same PII the deterministic rules cannot catch
(PERSON / ORG / LOC), but ships no spaCy dependency and takes any portable ONNX
model. `onnxruntime`/`numpy` are imported lazily and only when the tier is
constructed, so the base install stays pure-Python; enable it with
`pip install safestream-redactor[onnx]` and **bring your own model**.

```bash
safestream redact in.txt -o out.txt \
    --onnx model.onnx --onnx-vocab vocab.json      # --onnx-labels optional
```

```python
from safestream_redactor import Redactor
r = Redactor(use_onnx=True, onnx_model="model.onnx", onnx_vocab="vocab.json")
```

Three seams keep it testable and pluggable (`docs`/tests cover each): a
`Tokenizer` (built-in pure-Python `WordTokenizer`, or wrap a Hugging Face
sub-word tokenizer), an `InferenceBackend` (`OnnxRuntimeBackend`, or inject your
own), and a pure-Python `decode_bio` that merges BIO tags into character-offset
spans with a conservative (minimum-over-span) confidence. The tier declares
`StreamingRequirements` so the engine keeps it boundary-correct, and it pickles
its config (not the session) so it works under the parallel scheduler — exactly
like the spaCy tier. Labels default to the CoNLL IOB2 scheme
(`{0:"O",1:"B-PER",…}`); override with `--onnx-labels` (an id→tag JSON) for
another model. **No pretrained model is bundled** — the tier is the plumbing; the
accuracy is whatever model you supply.

**Getting a model.** `scripts/export_onnx.py` exports a Hugging Face
token-classification checkpoint (default `dslim/distilbert-NER`) with dynamic
batch/sequence axes, quantizes it to INT8 and writes the fast `tokenizer.json`
and `labels.json` next to it (export needs `torch` + `transformers`; running
needs only the `[onnx]` extra plus `tokenizers`). Passing that `tokenizer.json`
as the vocab selects the sub-word `HFTokenizer`, whose offsets index the original
text directly:

```bash
python scripts/export_onnx.py --out models/ner
safestream redact in.txt -o out.txt --onnx models/ner/model.int8.onnx \
    --onnx-vocab models/ner/tokenizer.json --onnx-labels models/ner/labels.json
```

**Gating and batching.** The model never sees the raw stream. A line reaches it
only if it holds a Titlecase word, a non-ASCII character, or a person cue
(`dr`, `patient`, `signed`, `dear`, ...), so machine text such as timestamps,
hex, ALLCAPS levels and paths costs one regex search. Gated lines are cut into
overlapping 500-character pieces, sorted by length, and run as padded batches
(one session call per 32 rows, one intra-op thread per worker process: scale
with `--workers`); softmax/argmax are NumPy array operations. A sub-word tag is
widened to the whole word, and a `B-` tag glued to the previous sub-word
continues it, so a name is never half-redacted.

**Recall-first threshold.** `--onnx-min-score` defaults to 0.35. A span that
clears it is emitted at confidence `max(score, 0.5)` (the raw score is in
`meta["onnx_score"]`), so the pipeline's default `min_confidence` does not undo
the lower threshold.

**Tier 0 wins overlaps.** When an NER span overlaps a deterministic/entropy
span, `resolve_overlaps` keeps one span covering both, labelled by the Tier-0
detection: a PERSON tag on `john.doe` cannot shrink the redaction of
`john.doe@example.com` and leave `@example.com` in the clear.

## Coverage and severity

Severity (`severity.py`) drives SARIF levels and MCP output. It is a static
property of the type, never of the matched text.

| Severity | Entity types |
| --- | --- |
| critical | `aws_key`, `aws_secret`, `private_key`, `github_token`, `slack_token`, `stripe_key`, `openai_key`, `anthropic_key`, `sendgrid_key`, `twilio_key`, `npm_token`, `google_api_key` |
| high | `slack_webhook`, `jwt`, `api_key`, `url_credentials`, `secret`, `ssn`, `credit_card` |
| medium | `email`, `phone`, `person`, `custom` |
| low | `ipv4`, `ipv6`, `org`, `loc` |

## Streaming requirements

Each detector declares a `StreamingRequirements` (`detectors/base.py`): the
longest span it can emit (`max_span`) and the left/right context it reads. The
engine derives its overlap from the maximum across the active detectors
(`engine.required_overlap`), so a detector's declared `max_span` is what
guarantees a boundary-split entity of that length is still seen whole. Setting an
overlap below the aggregate requirement logs a coverage warning.

| Detector | max_span | left/right context |
| --- | --- | --- |
| deterministic | 8192 | 0 / 0 |
| entropy | 8192 | 0 / 0 |
| compound_secret | 8192 | 0 / 0 |
| labeled_identifier | 64 | 96 / 8 |
| contextual | 9 | 48 / 0 |
| custom | 8192 | 0 / 0 |
| ner | 256 | 256 / 256 |

## Adding a detector

Use the `add-a-detector` workflow (`.claude/skills/add-a-detector/`), which walks
through: entity type + severity, an anchored and span-bounded pattern with a
validator, positive and **hard-negative** fixtures (UUIDs, git hashes, version
strings, base64 — the look-alikes that must not fire), a boundary-split test, and
the `pytest`/`ruff`/`mypy`/benchmark gates. Never weaken existing detection or a
threshold to make a new pattern look good.
