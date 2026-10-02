"""Optional local ONNX NER tier: on-device PII entity detection, no data egress.

Runs a local ONNX token-classification model (BIO/IOB2 tagging) entirely
on-device via ``onnxruntime`` — no network, no external services. It targets the
PII entities deterministic rules cannot reliably catch (PERSON / ORG / LOC): the
same niche as the spaCy NER tier, but with a portable ONNX model and no spaCy
dependency. ``onnxruntime`` and ``numpy`` are imported lazily and only when the
tier is actually constructed, so the core library stays dependency-free; install
with ``pip install safestream-redactor[onnx]`` and point it at a model.

Design — three seams, so the decode logic is testable without a model and any
tokenizer or model can be plugged in:

* :class:`Tokenizer` — text -> tokens with character offsets. The built-in
  :class:`WordTokenizer` is pure-Python (regex word/punct split + a vocab),
  deterministic, and enough to drive a word-level model; wrap a Hugging Face
  tokenizer for sub-word transformer models (its special tokens carry offset -1
  and are skipped).
* :class:`InferenceBackend` — token ids -> per-token logits.
  :class:`OnnxRuntimeBackend` loads a ``.onnx`` file and runs it on the CPU
  provider (local only, no remote execution provider).
* :func:`decode_bio` — a pure function turning per-token (argmax label,
  probability) into merged entity spans. No numpy, no onnxruntime; unit-tested
  directly with hand-built logits.

Local-first guarantee: the CPU execution provider does no network I/O, and the
tier runs happily under the default offline network guard (a differential test
exercises ``detect`` with the guard installed). No text ever leaves the process.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType

# --- token / model seams -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenSpan:
    """One model token and the half-open character span it covers in the text.

    ``start``/``end`` are character offsets into the original text. A special
    token (CLS/SEP/PAD, which has no text) carries ``start == -1`` and is treated
    as an entity boundary during decoding.
    """

    token_id: int
    start: int
    end: int

    @property
    def is_special(self) -> bool:
        return self.start < 0


@runtime_checkable
class Tokenizer(Protocol):
    """Text -> tokens with character offsets (the model's input alignment)."""

    def encode(self, text: str) -> list[TokenSpan]: ...


@runtime_checkable
class InferenceBackend(Protocol):
    """Token ids -> per-token logits (``len(input_ids)`` rows, one per token)."""

    def run(self, input_ids: list[int]) -> list[list[float]]: ...


# --- pure-Python BIO/IOB2 decoding (no numpy, no onnxruntime) ----------------


def _softmax(logits: list[float]) -> list[float]:
    """Numerically stable softmax over one token's logits."""
    hi = max(logits)
    exps = [math.exp(x - hi) for x in logits]
    total = sum(exps)
    return [e / total for e in exps] if total else [0.0 for _ in logits]


def _argmax(values: list[float]) -> int:
    best_i = 0
    best = values[0]
    for i, v in enumerate(values):
        if v > best:
            best, best_i = v, i
    return best_i


def split_label(label: str) -> tuple[str, str]:
    """Split a tag label into (prefix, entity_tag).

    Handles both IOB2 (``B-PER`` / ``I-PER``) and bare-tag schemes (``PER``).
    ``O`` (and the empty string) -> ``("O", "")``. A bare non-O tag is treated as
    a continuation marker so consecutive same-tag tokens merge into one span.
    """
    if label in ("O", ""):
        return "O", ""
    if "-" in label:
        prefix, _, tag = label.partition("-")
        return (prefix, tag) if prefix in ("B", "I") else ("I", label)
    return "I", label


def decode_bio(
    tokens: list[TokenSpan],
    per_token: list[tuple[int, float]],
    id2label: dict[int, str],
    tag_map: dict[str, EntityType],
    min_score: float,
) -> list[tuple[int, int, EntityType, float, str]]:
    """Merge per-token BIO predictions into entity spans (character offsets).

    ``per_token`` is ``(label_id, probability)`` per token, aligned to
    ``tokens``. Consecutive tokens of the same entity tag are merged; a ``B-``
    prefix, a tag change, a special token, or an ``O`` tag closes the current
    span. The span's confidence is the **mean** token probability across it: the
    tier is recall-first, and one uncertain sub-word (a rare surname piece) must
    not veto a name the other tokens are sure of. Spans below ``min_score`` or
    whose tag is not in ``tag_map`` are dropped.

    Returns ``(start, end, entity_type, confidence, tag)`` tuples.
    """
    results: list[tuple[int, int, EntityType, float, str]] = []
    cur_start = 0
    cur_end = 0
    cur_tag = ""
    cur_probs: list[float] = []

    def flush() -> None:
        nonlocal cur_tag, cur_probs
        if cur_tag:
            entity = tag_map.get(cur_tag)
            conf = sum(cur_probs) / len(cur_probs)
            if entity is not None and conf >= min_score:
                results.append((cur_start, cur_end, entity, conf, cur_tag))
        cur_tag = ""
        cur_probs = []

    # zip stops at the shorter of the two (defensive against a backend that
    # returns a wrong-length logit sequence); they are aligned in normal use.
    for tok, (label_id, prob) in zip(tokens, per_token, strict=False):
        prefix, tag = split_label(id2label.get(label_id, "O"))
        if tok.is_special or prefix == "O" or not tag:
            flush()
            continue
        # Some checkpoints tag every sub-word B- ("O" "lus" "eg" "un"); a B- glued
        # to the current span (no gap) is still the same word, so it continues.
        if prefix == "B" or not cur_tag or cur_tag != tag:
            if tag == cur_tag and tok.start == cur_end:
                cur_end = tok.end
                cur_probs.append(prob)
                continue
            flush()
            cur_start, cur_end, cur_tag, cur_probs = tok.start, tok.end, tag, [prob]
        else:  # I- continuing the same tag
            cur_end = tok.end
            cur_probs.append(prob)
    flush()
    return results


# --- built-in word-level tokenizer (pure Python) -----------------------------

_WORD_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


class WordTokenizer:
    """Regex word/punctuation tokenizer with character offsets and a vocab.

    Deterministic and dependency-free — enough to drive a word-level ONNX model
    and to test the whole pipeline. Out-of-vocabulary words map to ``<unk>``.
    """

    def __init__(
        self, vocab: dict[str, int], *, lowercase: bool = True, unk_token: str = "<unk>"
    ) -> None:
        self._vocab = dict(vocab)
        self._lowercase = lowercase
        self._unk = self._vocab.get(unk_token, 0)

    def encode(self, text: str) -> list[TokenSpan]:
        out: list[TokenSpan] = []
        for m in _WORD_RE.finditer(text):
            word = m.group()
            key = word.lower() if self._lowercase else word
            out.append(TokenSpan(self._vocab.get(key, self._unk), m.start(), m.end()))
        return out


class HFTokenizer:
    """A Hugging Face *fast* tokenizer (``tokenizer.json``) with character offsets.

    Sub-word models need their own tokenizer; the offsets it returns are character
    offsets into the very string passed in, so no text is re-assembled from tokens.
    Special tokens (CLS/SEP) carry ``start == -1``. Needs the ``tokenizers`` package
    (installed with ``transformers``); imported only when this class is constructed.
    """

    def __init__(self, tokenizer_file: str, max_length: int = 512) -> None:
        from tokenizers import Tokenizer as _HFTokenizer  # pragma: no cover - optional dep

        self._tok = _HFTokenizer.from_file(str(tokenizer_file))
        self._tok.no_padding()
        self._tok.enable_truncation(max_length)
        self.pad_id = next(
            (i for t in ("[PAD]", "<pad>") if (i := self._tok.token_to_id(t)) is not None), 0
        )

    def _spans(self, enc: Any) -> list[TokenSpan]:
        return [
            TokenSpan(i, -1 if special else s, -1 if special else e)
            for i, (s, e), special in zip(
                enc.ids, enc.offsets, enc.special_tokens_mask, strict=True
            )
        ]

    def encode(self, text: str) -> list[TokenSpan]:
        return self._spans(self._tok.encode(text))

    def encode_batch(self, texts: list[str]) -> list[list[TokenSpan]]:
        return [self._spans(e) for e in self._tok.encode_batch(texts)]


# --- Tier-1 gate: which spans are worth a model call --------------------------

# The model never reads the raw stream, nor whole lines: only short windows around
# a name-shaped candidate. Two triggers make a candidate:
#
# * a run of 2-4 Titlecase words (Latin incl. accented, Cyrillic): "Maria Gonzalez",
#   "Siobhan O'Neill", "José García-Márquez";
# * the words right after a person cue: "signed by", "Dr.", "patient:", ...
#   Honorifics must be capitalised (a log's "cache=MISS" or "41 ms" is not one), and
#   cues that are common in machine text ("user", "name", "contact") count only with
#   a colon, so "user login ok" and "name=foo" stay out. Only a sign-off
#   ("Regards,") reaches across a line break to the name below it.
#
# Timestamps, hex, ALLCAPS levels, paths and k=v pairs trigger neither, so most of
# a log costs one regex pass and no inference at all.
_UP = "A-ZÀ-ÖØ-ÞА-ЯЁ"
_LO = "a-zß-öø-ÿа-яё"
# "Smith", "Garcia-Marquez", "O'Neill" (accents included)
_NAME_WORD = (
    rf"[{_UP}](?:[{_LO}]{{1,40}}(?:['\u2019-][{_UP}]?[{_LO}]{{1,40}})*"
    rf"|['\u2019][{_UP}][{_LO}]{{1,40}})"
)
# a run of 2-4 Titlecase words, or one mid-sentence (after a lower-case word or a
# comma: "contact Alice and Bob"). A lone sentence-initial word ("Rollback is ...")
# is not a candidate: in prose that is nearly every sentence.
_TITLE_RUN_RE = re.compile(
    rf"(?<!\w)(?:{_NAME_WORD}(?:[ \t]+{_NAME_WORD}){{1,3}}|(?<=[a-z,][ \t]){_NAME_WORD})(?!\w)"
)
_CUE_RE = re.compile(
    r"(?<!\w)(?:(?:Dr|Mrs?|Ms|Prof|Dear|Attn|(?i:signed[ \t]+by))\b[.,:]?[ \t]*"
    r"|(?i:sincerely|regards)\b,?[ \t]*\n?[ \t]*"
    r"|(?i:name|patient|witness|user|contact|employee|customer|client|applicant|author"
    r"|nurse|physician|cc)[ \t]*:[ \t]*)"
)
# up to three words after a cue: the name (in any case) and nothing past a stopword
_AFTER_CUE_RE = re.compile(r"[^\W\d_][\w'\u2019-]{0,39}(?:[ \t]+[^\W\d_][\w'\u2019-]{0,39}){0,2}")
_STOPWORDS = frozenset(
    {"a", "an", "and", "at", "by", "for", "from", "in", "of", "on", "or", "our", "the",
     "their", "this", "to", "with", "your", "his", "her", "was", "is", "has", "had",
     "will", "behalf"}
)  # fmt: skip
# characters of context on each side of a candidate (about 8-12 words)
_CONTEXT = 32


def _cue_name(text: str, pos: int) -> list[tuple[int, int]]:
    """Spans of the name words right after a cue that ends at ``pos``."""
    m = _AFTER_CUE_RE.match(text, pos)
    if m is None:
        return []
    words: list[tuple[int, int]] = []
    for w in re.finditer(r"\S+", m.group()):
        if w.group().lower() in _STOPWORDS:
            break
        words.append((pos + w.start(), pos + w.end()))
    return words


def _candidate_windows(text: str) -> list[tuple[int, str]]:
    """``(offset, model input)`` windows around every name candidate in ``text``.

    The model input is the window text, except that lower-case words after a cue
    are capitalised (``signed by john smith`` -> ``John Smith``) so a cased model
    can see them as names. Capitalising one character keeps the length, so the
    model's offsets are offsets into ``text`` unchanged.
    """
    spans: list[tuple[int, int]] = []
    recase: list[int] = []  # positions whose character is upper-cased for the model
    for m in _TITLE_RUN_RE.finditer(text):
        spans.append((m.start(), m.end()))
    for m in _CUE_RE.finditer(text):
        words = _cue_name(text, m.end())
        if not words:
            continue
        spans.append((m.start(), words[-1][1]))
        for ws, we in words:
            word = text[ws:we]
            if word.islower() and len(word[0].upper()) == 1:
                recase.append(ws)
    if not spans:
        return []
    # widen by the context (within the line), then merge overlapping windows
    windows: list[list[int]] = []
    for s, e in sorted(spans):
        line_start = text.rfind("\n", 0, s) + 1
        line_end = text.find("\n", e)
        lo = max(line_start, s - _CONTEXT)
        hi = min(len(text) if line_end < 0 else line_end, e + _CONTEXT)
        lo, hi = _snap_to_words(text, lo, hi)
        if windows and lo <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], hi)
        else:
            windows.append([lo, hi])
    recase_set = set(recase)
    out: list[tuple[int, str]] = []
    for lo, hi in windows:
        piece = text[lo:hi]
        if recase_set:
            chars = list(piece)
            for i in range(lo, hi):
                if i in recase_set:
                    chars[i - lo] = chars[i - lo].upper()
            piece = "".join(chars)
        out.append((lo, piece))
    return out


# --- onnxruntime backend (lazy, local-only) ----------------------------------


def _lazy_imports() -> tuple[Any, Any]:  # pragma: no cover - requires the [onnx] extra
    try:
        import numpy as np
        import onnxruntime as ort
    except ImportError as exc:
        raise ImportError(
            "The ONNX NER tier needs onnxruntime and numpy. Install them with "
            "'pip install safestream-redactor[onnx]'."
        ) from exc
    return ort, np


def _load_json_map(source: str | dict[Any, Any]) -> dict[Any, Any]:
    """Return ``source`` if it is already a dict, else load it as a JSON file."""
    if isinstance(source, dict):
        return source
    loaded: dict[Any, Any] = json.loads(Path(source).read_text(encoding="utf-8"))
    return loaded


def _first_present(names: set[str], candidates: tuple[str, ...]) -> str | None:
    for c in candidates:
        if c in names:
            return c
    return None


class OnnxRuntimeBackend:
    """Runs a local ``.onnx`` token-classifier on the CPU provider (no network).

    Input/output tensor names are auto-detected from the model but can be
    overridden. The model is expected to emit logits shaped ``(batch, seq,
    num_labels)`` (a leading batch dimension is optional).
    """

    def __init__(  # pragma: no cover - requires the [onnx] extra
        self,
        model_path: str,
        *,
        input_name: str | None = None,
        attention_mask_name: str | None = None,
        output_name: str | None = None,
        providers: list[str] | None = None,
        threads: int = 1,
    ) -> None:
        ort, np = _lazy_imports()
        self._np = np
        opts = ort.SessionOptions()
        # One worker process = one core: scale out with --workers, which
        # parallelizes the whole pipeline, rather than oversubscribing cores
        # with intra-op threads in every worker.
        opts.intra_op_num_threads = threads
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # CPU provider only: no remote/execution-provider egress.
        self._session = ort.InferenceSession(
            str(model_path), sess_options=opts, providers=providers or ["CPUExecutionProvider"]
        )
        inputs = self._session.get_inputs()
        input_names = {i.name for i in inputs}
        # BERT-family exports also take token_type_ids; a single segment is all zeros
        self._type_ids_name = "token_type_ids" if "token_type_ids" in input_names else None
        # a model exported with a fixed batch dimension of 1 is fed one row at a time
        batch_dim = inputs[0].shape[0] if inputs[0].shape else None
        self.max_batch = 1 if batch_dim == 1 else 32
        resolved_input = input_name or _first_present(
            input_names, ("input_ids", "input", "ids", "tokens")
        )
        if resolved_input is None:  # pragma: no cover - malformed model
            raise ValueError(
                f"could not find an input tensor in {model_path}; "
                f"inputs are {sorted(input_names)}. Pass input_name= explicitly."
            )
        self._input_name = resolved_input
        self._mask_name = attention_mask_name or _first_present(
            input_names, ("attention_mask", "mask")
        )
        self._output_name = output_name or self._session.get_outputs()[0].name

    def run(self, input_ids: list[int]) -> list[list[float]]:  # pragma: no cover
        np = self._np
        arr = np.asarray([input_ids], dtype=np.int64)  # (1, seq)
        feed: dict[str, Any] = {self._input_name: arr}
        if self._mask_name is not None:
            feed[self._mask_name] = np.ones_like(arr)
        out = self._session.run([self._output_name], feed)[0]
        logits = np.asarray(out)
        if logits.ndim == 3:  # (batch, seq, labels) -> drop batch
            logits = logits[0]
        return [[float(x) for x in row] for row in logits]

    def predict_batch(
        self, batch: list[list[int]], pad_id: int, outside_id: int
    ) -> list[tuple[list[int], list[float]] | None]:  # pragma: no cover - [onnx] extra
        """Per row: ``(label ids, label probabilities)``, or ``None`` if all ``O``.

        One padded inference call for the whole batch; softmax, argmax and the
        all-``O`` test are array operations, so Python only touches rows that
        hold an entity.
        """
        np = self._np
        lengths = np.fromiter(map(len, batch), dtype=np.int64, count=len(batch))
        ids = np.full((len(batch), int(lengths.max())), pad_id, dtype=np.int64)
        mask = np.arange(ids.shape[1]) < lengths[:, None]
        ids[mask] = np.fromiter(
            (t for row in batch for t in row), dtype=np.int64, count=int(lengths.sum())
        )
        feed: dict[str, Any] = {self._input_name: ids}
        if self._mask_name is not None:
            feed[self._mask_name] = mask.astype(np.int64)
        if self._type_ids_name is not None:
            feed[self._type_ids_name] = np.zeros_like(ids)
        logits = np.asarray(self._session.run([self._output_name], feed)[0], dtype=np.float32)
        if logits.ndim == 2:  # model without a batch dimension
            logits = logits[None]
        labels = logits.argmax(-1)
        # max softmax probability = 1 / sum(exp(logit - max logit))
        probs = 1.0 / np.exp(logits - logits.max(-1, keepdims=True)).sum(-1)
        has_entity = ((labels != outside_id) & mask).any(-1)
        return [
            (labels[i, :n].tolist(), probs[i, :n].tolist()) if has_entity[i] else None
            for i, n in enumerate(lengths.tolist())
        ]


# --- default label scheme ----------------------------------------------------

# Standard CoNLL-style IOB2 ordering; override via id2label= for another model.
_DEFAULT_ID2LABEL: dict[int, str] = {
    0: "O",
    1: "B-PER",
    2: "I-PER",
    3: "B-ORG",
    4: "I-ORG",
    5: "B-LOC",
    6: "I-LOC",
}

# entity tag -> SafeStream EntityType. Covers the common CoNLL / OntoNotes tags.
_DEFAULT_TAG_MAP: dict[str, EntityType] = {
    "PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORG,
    "ORGANIZATION": EntityType.ORG,
    "LOC": EntityType.LOC,
    "LOCATION": EntityType.LOC,
    "GPE": EntityType.LOC,
    "FAC": EntityType.LOC,
}


def _normalize_tag_map(
    tag_map: dict[str, EntityType | str] | None,
) -> dict[str, EntityType]:
    if tag_map is None:
        return dict(_DEFAULT_TAG_MAP)
    out: dict[str, EntityType] = {}
    for tag, et in tag_map.items():
        out[tag] = et if isinstance(et, EntityType) else EntityType.from_name(et)
    return out


class OnnxPiiDetector:
    """Local ONNX token-classification tier for PERSON / ORG / LOC entities.

    Two ways to construct it:

    * production — ``OnnxPiiDetector(model_path=..., vocab=...)`` builds an
      :class:`OnnxRuntimeBackend` and a :class:`WordTokenizer` internally. This
      form is picklable (it stores its construction kwargs and rebuilds per
      worker), so it works with the parallel scheduler.
    * injected — pass ``backend=`` and/or ``tokenizer=`` to plug in a Hugging
      Face tokenizer or a custom model runner (and for testing). This form is
      single-process only; pickling it raises a clear error.

    The tier is stateless per :meth:`detect` call and declares the context it
    reads so the streaming engine sizes its overlap correctly.
    """

    name = "onnx"
    # Named entities are short; like the spaCy tier the model reads sentence
    # context on both sides, so declare a modest window. Accuracy can still
    # degrade right at a chunk boundary — a known limitation the context
    # mitigates but does not eliminate (see docs/DETECTORS.md).
    requirements = StreamingRequirements(max_span=256, left_context=256, right_context=256)

    def __init__(
        self,
        model_path: str | None = None,
        *,
        vocab: dict[str, int] | None = None,
        id2label: dict[int, str] | None = None,
        tag_map: dict[str, EntityType | str] | None = None,
        min_score: float = 0.35,
        confidence: float | None = None,
        model_name: str | None = None,
        lowercase: bool = True,
        input_name: str | None = None,
        output_name: str | None = None,
        attention_mask_name: str | None = None,
        providers: list[str] | None = None,
        tokenizer_file: str | None = None,
        threads: int = 1,
        backend: InferenceBackend | None = None,
        tokenizer: Tokenizer | None = None,
    ) -> None:
        self._id2label = {int(k): v for k, v in (id2label or _DEFAULT_ID2LABEL).items()}
        self._tag_map = _normalize_tag_map(tag_map)
        self._min_score = min_score
        self._outside_id = next((k for k, v in self._id2label.items() if v == "O"), 0)
        # optional fixed confidence: emit this instead of the model probability
        # (parity with the spaCy tier, which assigns a constant confidence).
        self._fixed_confidence = confidence
        self._model_name = model_name or (str(model_path) if model_path else "onnx")

        injected = backend is not None or tokenizer is not None
        self._picklable = not injected
        # Kwargs to rebuild an equivalent detector (per-worker) — only for the
        # production, file-based form. Injected components can't be pickled.
        self._config: dict[str, Any] = {
            "model_path": model_path,
            "vocab": vocab,
            "id2label": id2label,
            "tag_map": {t: e.value for t, e in self._tag_map.items()},
            "min_score": min_score,
            "confidence": confidence,
            "model_name": model_name,
            "lowercase": lowercase,
            "input_name": input_name,
            "output_name": output_name,
            "attention_mask_name": attention_mask_name,
            "providers": providers,
            "tokenizer_file": tokenizer_file,
            "threads": threads,
        }

        if tokenizer is not None:
            self._tokenizer: Tokenizer = tokenizer
        elif tokenizer_file is not None:
            self._tokenizer = HFTokenizer(tokenizer_file)
        else:
            if vocab is None:
                raise ValueError(
                    "vocab= is required unless a tokenizer= or tokenizer_file= is provided"
                )
            self._tokenizer = WordTokenizer(vocab, lowercase=lowercase)

        if backend is not None:
            self._backend: InferenceBackend = backend
        else:
            if model_path is None:
                raise ValueError("model_path= is required unless a backend= is provided")
            self._backend = OnnxRuntimeBackend(  # pragma: no cover - requires the [onnx] extra
                model_path,
                input_name=input_name,
                attention_mask_name=attention_mask_name,
                output_name=output_name,
                providers=providers,
                threads=threads,
            )
        self._pad_id: int = getattr(self._tokenizer, "pad_id", 0)

    # Parallel scheduler ships detectors to worker processes. An onnxruntime
    # session isn't picklable, so (as the spaCy tier does) pickle only the config
    # and rebuild the model in each worker.
    @classmethod
    def from_files(  # pragma: no cover - builds a real backend; requires the [onnx] extra
        cls,
        model_path: str,
        vocab: str | dict[str, int],
        labels: str | dict[int | str, str] | None = None,
        **kwargs: Any,
    ) -> OnnxPiiDetector:
        """Build a detector from a ``.onnx`` file, a JSON vocab, and optional labels.

        ``vocab`` and ``labels`` may be paths to JSON files or already-loaded
        dicts, so the CLI/config can pass file paths and library callers can pass
        objects. A ``vocab`` path to a Hugging Face ``tokenizer.json`` (what
        ``scripts/export_onnx.py`` writes) selects the sub-word :class:`HFTokenizer`.
        ``labels`` (id -> tag, e.g. ``{"1": "B-PER"}``) defaults to the CoNLL IOB2
        scheme when omitted.
        """
        id2label = None
        if labels is not None:
            id2label = {int(k): str(v) for k, v in _load_json_map(labels).items()}
        if isinstance(vocab, str) and Path(vocab).name == "tokenizer.json":
            return cls(model_path=model_path, tokenizer_file=vocab, id2label=id2label, **kwargs)
        vocab_map = {str(k): int(v) for k, v in _load_json_map(vocab).items()}
        return cls(model_path=model_path, vocab=vocab_map, id2label=id2label, **kwargs)

    def __getstate__(self) -> dict[str, Any]:
        if not self._picklable:
            raise TypeError(
                "OnnxPiiDetector built with an injected backend/tokenizer is not picklable; "
                "construct it with model_path= and vocab= for parallel use."
            )
        return dict(self._config)  # pragma: no cover - file-based detector needs the [onnx] extra

    def __setstate__(self, state: dict[str, Any]) -> None:  # pragma: no cover - [onnx] extra
        self.__init__(**state)  # type: ignore[misc]

    def detect(self, text: str) -> list[Detection]:
        """Run the model on the candidate windows of ``text`` only (see ``_candidate_windows``)."""
        pieces = _candidate_windows(text)
        if not pieces:
            return []
        encode_batch = getattr(self._tokenizer, "encode_batch", None)
        texts = [piece for _, piece in pieces]
        encoded = (
            encode_batch(texts) if encode_batch else [self._tokenizer.encode(t) for t in texts]
        )
        predictions = self._predict([[t.token_id for t in tokens] for tokens in encoded])
        found: list[Detection] = []
        seen: set[tuple[int, int, EntityType]] = set()
        for (offset, _), tokens, pred in zip(pieces, encoded, predictions, strict=True):
            if pred is None:
                continue
            spans = decode_bio(
                tokens,
                list(zip(*pred, strict=True)),
                self._id2label,
                self._tag_map,
                self._min_score,
            )
            for start, end, entity, score, tag in spans:
                start, end = _snap_to_words(text, offset + start, offset + end)
                if (start, end, entity) in seen:  # overlapping pieces, split sub-words
                    continue
                seen.add((start, end, entity))
                found.append(
                    Detection(
                        start=start,
                        end=end,
                        text=text[start:end],
                        entity_type=entity,
                        # a span that cleared min_score is a decision: emit it at
                        # least at the pipeline's default min_confidence, so a low
                        # recall-first threshold is not silently undone downstream
                        confidence=self._fixed_confidence
                        if self._fixed_confidence is not None
                        else max(score, _DECIDED_FLOOR),
                        source=self.name,
                        meta={
                            "onnx_label": tag,
                            "onnx_score": f"{score:.3f}",
                            "model": self._model_name,
                        },
                    )
                )
        return _join_spaced(text, found)

    def _predict(self, batch: list[list[int]]) -> list[tuple[list[int], list[float]] | None]:
        """Per token-id row: ``(labels, probabilities)``, or ``None`` when all ``O``."""
        out: list[tuple[list[int], list[float]] | None] = [None] * len(batch)
        rows = [i for i, ids in enumerate(batch) if ids]
        predict_batch = getattr(self._backend, "predict_batch", None)
        if predict_batch is None:  # a backend with only run(): one row at a time
            for i in rows:
                probs = [_softmax(row) for row in self._backend.run(batch[i])]
                labels = [_argmax(p) for p in probs]
                if any(lab != self._outside_id for lab in labels):
                    out[i] = (labels, [p[lab] for p, lab in zip(probs, labels, strict=True)])
            return out
        # similar lengths share a batch, so little of each batch is padding
        rows.sort(key=lambda i: len(batch[i]))
        size = getattr(self._backend, "max_batch", 32)
        for k in range(0, len(rows), size):
            chunk = rows[k : k + size]
            results = predict_batch([batch[i] for i in chunk], self._pad_id, self._outside_id)
            for i, res in zip(chunk, results, strict=True):
                out[i] = res
        return out


_DECIDED_FLOOR = 0.5


def _join_spaced(text: str, found: list[Detection]) -> list[Detection]:
    """Merge name parts the model tagged separately ("Olusegun" "Tanaka").

    Two spans with only a space or tab between them become one, so the output is
    a single redaction (it does not reveal how many words a name has), labelled
    by the more confident part.
    """
    found.sort(key=lambda d: d.start)
    out: list[Detection] = []
    for det in found:
        prev = out[-1] if out else None
        if prev is not None and prev.end <= det.start <= prev.end + 2:
            gap = text[prev.end : det.start]
            if gap.strip(" \t") == "":
                best = prev if prev.confidence >= det.confidence else det
                end = max(prev.end, det.end)
                out[-1] = Detection(
                    prev.start, end, text[prev.start : end], best.entity_type,
                    best.confidence, best.source, dict(best.meta),
                )  # fmt: skip
                continue
        out.append(det)
    return out


# ponytail: snapping stops after this many characters each way, so a name tag
# inside a huge base64 blob cannot grow past the tier's declared max_span.
_SNAP_LIMIT = 32


def _snap_to_words(text: str, start: int, end: int) -> tuple[int, int]:
    """Widen a span to whole words: a sub-word tag must not leave half a name."""
    lo = max(0, start - _SNAP_LIMIT)
    while start > lo and text[start - 1].isalnum():
        start -= 1
    hi = min(len(text), end + _SNAP_LIMIT)
    while end < hi and text[end].isalnum():
        end += 1
    return start, end
