"""The main user-facing API: the :class:`Redactor`."""

from __future__ import annotations

import logging
import os
from bisect import bisect_right, insort
from collections.abc import Iterable, Iterator
from dataclasses import replace

from safestream_redactor._atomic import atomic_output
from safestream_redactor.calibration import Calibrator
from safestream_redactor.detectors.base import Detector
from safestream_redactor.detectors.contextual import ContextualScorer
from safestream_redactor.detectors.custom import CustomDetector
from safestream_redactor.detectors.deterministic import DeterministicDetector
from safestream_redactor.engine import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP,
    read_chunks,
    stream_transform,
    stream_windows,
)
from safestream_redactor.entities import Detection, EntityType, resolve_overlaps
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.report import RedactionStats

logger = logging.getLogger(__name__)


def _validate_streaming_args(chunk_size: object, overlap: object, min_confidence: object) -> None:
    """Reject argument values that would silently corrupt or drop output.

    ``chunk_size=0`` made every reader return an empty first read, so the
    whole input vanished and an empty "redacted" file was written; a negative
    one read the entire file at once, defeating the memory bound. Neither is a
    meaningful configuration, so both fail closed here — once, for every entry
    point (library, CLI, config file, REST, MCP).
    """
    # bool is an int subclass; ``chunk_size=True`` is a bug, not a size
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size!r}")
    if isinstance(overlap, bool) or not isinstance(overlap, int) or overlap < 0:
        raise ValueError(f"overlap must be a non-negative integer, got {overlap!r}")
    if (
        isinstance(min_confidence, bool)
        or not isinstance(min_confidence, (int, float))
        or not 0.0 <= min_confidence <= 1.0
    ):
        raise ValueError(f"min_confidence must be a number in [0, 1], got {min_confidence!r}")


def _merge_statistical(text: str, kept: list[Detection], ner: list[Detection]) -> list[Detection]:
    """Add spaCy detections to ``kept`` without letting them displace any of it.

    spaCy's span boundaries are approximate: it can tag ``kowalski,+53`` as one
    entity, swallowing the head of a phone number. Under plain overlap
    resolution that span (confidence 0.7) beat the lower-confidence phone match,
    so the rest of the number went out unredacted. Here the rule-based spans are
    resolved first and kept whole, and each spaCy span (best first) contributes
    only the parts of itself that nothing kept so far covers. The redacted
    characters are therefore a superset of what the rule-based tiers alone
    redact: turning the NER tier on can only add redaction, never remove it.
    """
    spans = sorted((d.start, d.end) for d in kept)
    out = list(kept)
    for det in sorted(ner, key=lambda d: (-d.confidence, d.start - d.end, d.start)):
        pos = det.start
        # every kept span that overlaps [det.start, det.end), in order
        i = bisect_right(spans, (det.start,))
        if i and spans[i - 1][1] > det.start:
            i -= 1
        pieces: list[tuple[int, int]] = []
        while i < len(spans) and spans[i][0] < det.end:
            if spans[i][0] > pos:
                pieces.append((pos, spans[i][0]))
            pos = max(pos, spans[i][1])
            i += 1
        if pos < det.end:
            pieces.append((pos, det.end))
        for start, end in pieces:
            # a sliver of separators between two kept spans redacts nothing useful
            if not any(c.isalnum() for c in text[start:end]):
                continue
            insort(spans, (start, end))
            if (start, end) == (det.start, det.end):
                out.append(det)
            else:
                meta = {**det.meta, "clipped": "true"}
                out.append(replace(det, start=start, end=end, text=text[start:end], meta=meta))
    out.sort(key=lambda d: d.start)
    return out


class Redactor:
    """Detects and redacts sensitive entities in strings, streams, and files.

    Parameters
    ----------
    types:
        Entity types to detect (names or :class:`EntityType`); ``None`` means all
        deterministic types.
    policy:
        How detections are rewritten; defaults to replacing with ``[REDACTED]``.
    min_confidence:
        Detections scoring below this (after contextual adjustment) are ignored.
    custom_words / custom_patterns:
        Extra literal words/phrases and regexes to always redact.
    use_ner:
        The spaCy PERSON/ORG/LOC tier, **on by default** (independent of
        ``types``, like the other name tiers). spaCy is a required dependency;
        the model named by ``ner_model`` is installed with
        ``python -m spacy download en_core_web_sm``. If it cannot be loaded,
        construction raises :class:`~safestream_redactor.detectors.ner.NERUnavailableError`
        rather than running without name coverage. Pass ``False`` only to
        knowingly give up name/organisation/location redaction.
    use_onnx:
        Enable the optional local ONNX NER tier (PERSON/ORG/LOC via an on-device
        ONNX model, no data egress; requires the ``onnx`` extra). Needs
        ``onnx_model`` and ``onnx_vocab``; ``onnx_labels`` (id->tag JSON) is
        optional and defaults to the CoNLL IOB2 scheme.
    use_entropy:
        Enable the statistical tier that flags high-entropy secrets with no
        published format (on by default).
    calibrator:
        Optional trained :class:`~safestream_redactor.calibration.Calibrator`.
        When given, each detection's hand-set confidence is replaced by the
        model's calibrated probability before ``min_confidence`` is applied, so
        the threshold acts on comparable probabilities across tiers. Calibration
        is a per-detection function of local features only, so it preserves the
        streaming/parallel equivalence guarantees.
    extra_detectors:
        Any additional objects implementing the :class:`Detector` protocol.
    load_plugins:
        Discover and load third-party detectors registered under the
        ``safestream_redactor.detectors`` entry-point group. **Off by default**:
        plugin code runs with full process privileges, so it must be trusted
        explicitly. When it is off and plugins are installed, a one-time warning
        names them so the reduced coverage is never silent.
    allow_unsafe_overlap:
        Off by default (fail-closed). When ``overlap`` is below the safe minimum
        the active detectors require (:attr:`min_safe_overlap`), construction
        raises ``ValueError`` rather than silently risking a boundary-induced
        redaction leak. Set this to ``True`` to knowingly accept the unsafe
        regime (e.g. a boundary test on entities known to be short); the guard
        then only logs a warning, restoring the pre-fail-closed behaviour.
    backend:
        Detection engine for the deterministic tier. ``"python"`` (default) runs
        everything in pure Python. ``"native"``/``"auto"`` route the patterns the
        optional compiled core covers through it and the rest through Python, with
        byte-identical output; both fall back to pure Python when the
        ``safestream_native`` extension is not installed (``"native"`` warns).
    """

    def __init__(
        self,
        types: Iterable[EntityType | str] | None = None,
        policy: RedactionPolicy | None = None,
        min_confidence: float = 0.5,
        custom_words: Iterable[str] = (),
        custom_patterns: Iterable[str] = (),
        use_ner: bool = True,
        ner_model: str = "en_core_web_sm",
        use_gazetteer: bool = False,
        use_ensemble: bool = False,
        semantic_policy: str = "strict",
        use_onnx: bool = False,
        onnx_model: str | None = None,
        onnx_vocab: str | dict[str, int] | None = None,
        onnx_labels: str | dict[int | str, str] | None = None,
        onnx_min_score: float = 0.5,
        use_entropy: bool = True,
        calibrator: Calibrator | None = None,
        extra_detectors: Iterable[Detector] = (),
        load_plugins: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = DEFAULT_OVERLAP,
        allow_unsafe_overlap: bool = False,
        backend: str = "python",
    ) -> None:
        resolved_types = (
            None
            if types is None
            else [t if isinstance(t, EntityType) else EntityType.from_name(t) for t in types]
        )
        _validate_streaming_args(chunk_size, overlap, min_confidence)
        self.policy = policy or RedactionPolicy()
        self.min_confidence = min_confidence
        self.calibrator = calibrator
        self.chunk_size = chunk_size
        self.overlap = overlap
        self._scorer = ContextualScorer()

        self._detectors: list[Detector] = [DeterministicDetector(resolved_types, backend=backend)]
        # Label-anchored identifier cascade: a high-precision contextual tier that
        # promotes otherwise-ambiguous values (bare id/account/DOB numbers) to
        # redactions only when a cue word names them. On by default; it emits its
        # own entity types (plus SSN/PHONE/CREDIT_CARD), so it is active whenever
        # any of those are in scope, or when no explicit type filter is set.
        from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector

        _labeled_types = {
            EntityType.SSN,
            EntityType.PHONE,
            EntityType.CREDIT_CARD,
            EntityType.DOB,
            EntityType.ID_NUMBER,
        }
        if resolved_types is None or _labeled_types.intersection(resolved_types):
            self._detectors.append(LabeledIdentifierDetector())
        custom_words = list(custom_words)
        custom_patterns = list(custom_patterns)
        if custom_words or custom_patterns:
            self._detectors.append(CustomDetector(custom_words, custom_patterns))
        if use_ner:
            from safestream_redactor.detectors.ner import NERDetector

            self._detectors.append(NERDetector(ner_model))
        if use_gazetteer:
            from safestream_redactor.detectors.gazetteer_ner import GazetteerNameDetector

            self._detectors.append(GazetteerNameDetector())
        if use_ensemble:
            from safestream_redactor.detectors.semantic_ensemble import SemanticEnsembleDetector

            self._detectors.append(SemanticEnsembleDetector(policy=semantic_policy))
        if use_onnx:
            from safestream_redactor.detectors.onnx_ner import OnnxPiiDetector

            if onnx_model is None or onnx_vocab is None:
                raise ValueError("use_onnx requires onnx_model and onnx_vocab")
            self._detectors.append(
                OnnxPiiDetector.from_files(
                    onnx_model, onnx_vocab, onnx_labels, min_score=onnx_min_score
                )
            )
        # statistical tier: generic high-entropy secrets (on by default). The
        # compound-secret tier closes the symbol-containing-secret gap the base
        # entropy candidate splits on (see detectors/entropy.py); both are gated
        # by the same use_entropy / SECRET-in-scope condition.
        if use_entropy and (resolved_types is None or EntityType.SECRET in resolved_types):
            from safestream_redactor.detectors.entropy import (
                CompoundSecretDetector,
                EntropyDetector,
            )

            self._detectors.append(EntropyDetector())
            self._detectors.append(CompoundSecretDetector())
        self._detectors.extend(extra_detectors)
        # third-party detectors registered via entry points (opt-in)
        if load_plugins:
            from safestream_redactor.detectors.registry import load_plugins as _load_plugins

            self._detectors.extend(_load_plugins())
        else:
            from safestream_redactor.detectors.registry import warn_if_plugins_skipped

            warn_if_plugins_skipped()
        # contextual tier also contributes trigger-gated detections of its own
        if resolved_types is None or EntityType.SSN in resolved_types:
            self._detectors.append(self._scorer)
        logger.debug("detector tiers active: %s", [d.name for d in self._detectors])

        self.enforce_overlap_safety(allow_unsafe_overlap)

    def enforce_overlap_safety(self, allow_unsafe: bool = False) -> None:
        """Fail closed unless ``overlap`` covers what the active detectors require.

        The overlap must be at least :attr:`min_safe_overlap` — the largest span
        any active detector can emit *plus the context it reads*, derived from
        each tier's declared :class:`StreamingRequirements`. Below it, an entity
        that straddles a chunk boundary can be missed and streaming output can
        diverge from a whole-document pass — a redaction leak
        (``docs/FORMAL_MODEL.md``, Theorem 1's premise). Because this is a privacy
        tool the default is to **raise**; a caller that knowingly wants the unsafe
        regime (e.g. a boundary test on short entities) passes ``allow_unsafe`` to
        downgrade the error to a warning. Callers that mutate ``overlap`` or the
        detector set after construction (the CLI does) should re-invoke this.
        """
        needed = self.min_safe_overlap
        if self.overlap >= needed:
            return
        names = ", ".join(sorted({d.name for d in self._detectors}))
        if allow_unsafe:
            logger.warning(
                "overlap=%d is below the %d characters the active detectors require "
                "(%s); entities longer than the overlap that straddle a chunk boundary "
                "may be missed. Proceeding because allow_unsafe_overlap=True.",
                self.overlap,
                needed,
                names,
            )
            return
        raise ValueError(
            f"overlap={self.overlap} is below the {needed}-character safe minimum "
            f"required by the active detectors ({names}). At a smaller overlap an "
            "entity that straddles a chunk boundary can be missed and streaming "
            "output can diverge from a whole-document pass (a redaction leak). "
            f"Raise overlap to at least {needed}, or pass allow_unsafe_overlap=True "
            "to override (not recommended for redaction)."
        )

    @property
    def detector_names(self) -> list[str]:
        """Names of the detector tiers active on this redactor, in run order."""
        return [d.name for d in self._detectors]

    @property
    def min_safe_overlap(self) -> int:
        """Smallest overlap that keeps every active detector boundary-correct.

        Derived from each detector's declared
        :class:`~safestream_redactor.detectors.base.StreamingRequirements`
        rather than a global constant. An ``overlap`` at least this large
        guarantees any entity the active tiers can emit is seen whole even when
        split across a chunk boundary.
        """
        from safestream_redactor.engine import required_overlap

        return required_overlap(self._detectors)

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[Detection]:
        """All detections in ``text``, scored, filtered, and non-overlapping."""
        raw: list[Detection] = []
        for detector in self._detectors:
            raw.extend(detector.detect(text))
        self._scorer.adjust(text, raw)
        if self.calibrator is not None:
            for det in raw:
                det.confidence = self.calibrator.predict_one(det)
        confident = [d for d in raw if d.confidence >= self.min_confidence]
        kept = resolve_overlaps([d for d in confident if d.source != "ner"])
        ner = [d for d in confident if d.source == "ner"]
        return _merge_statistical(text, kept, ner) if ner else kept

    # ------------------------------------------------------------------
    # redaction
    # ------------------------------------------------------------------

    def redact(self, text: str) -> str:
        """Redact a string held fully in memory."""
        return self.policy.apply(text, self.detect(text))

    def detect_stream(self, chunks: Iterable[str]) -> Iterator[tuple[str, list[Detection]]]:
        """Stream detection without redacting.

        Yields ``(segment, detections)`` pairs; segments concatenate to the
        full input, and each detection's offsets are relative to its segment.
        """
        return stream_windows(chunks, self.detect, self.overlap, min_emit=self.chunk_size)

    def redact_stream(
        self, chunks: Iterable[str], stats: RedactionStats | None = None
    ) -> Iterator[str]:
        """Redact an iterable/generator of text chunks, yielding redacted chunks.

        Memory stays bounded by ``chunk_size + overlap`` regardless of total
        input size. Entities up to ``overlap`` characters long are detected
        even when split across chunk boundaries. Pass a
        :class:`~safestream_redactor.report.RedactionStats` to accumulate
        per-type counts and sizes while streaming.
        """
        if stats is None:
            return stream_transform(
                chunks, self.detect, self.policy.apply, self.overlap, min_emit=self.chunk_size
            )
        return self._redact_stream_with_stats(chunks, stats)

    def _redact_stream_with_stats(
        self, chunks: Iterable[str], stats: RedactionStats
    ) -> Iterator[str]:
        for segment, detections in stream_windows(
            chunks, self.detect, self.overlap, min_emit=self.chunk_size
        ):
            redacted = self.policy.apply(segment, detections)
            stats.add_segment(segment, redacted, detections)
            yield redacted

    def redact_file(
        self,
        input_path: str | os.PathLike[str],
        output_path: str | os.PathLike[str],
        encoding: str = "utf-8",
        *,
        workers: int | None = None,
    ) -> RedactionStats:
        """Redact ``input_path`` into ``output_path`` without loading either fully.

        The output is written to a temporary file in the destination directory
        and moved into place atomically, so a crash mid-run can never leave a
        partially redacted file that looks complete — downstream consumers see
        either the old content or the fully redacted result. Redacting a file
        onto itself is rejected (the source would be destroyed on failure).

        ``workers`` > 1 redacts a large file with that many processes in
        parallel (see :mod:`safestream_redactor.parallel`); the output is
        byte-identical to the sequential pass, and small files or encodings
        that cannot be split safely fall back to it automatically.

        Returns the run's :class:`~safestream_redactor.report.RedactionStats`
        (per-type counts, characters in/out).
        """
        if workers is not None and workers > 1:
            from safestream_redactor.parallel import redact_file_parallel

            return redact_file_parallel(
                self, input_path, output_path, workers=workers, encoding=encoding
            ).stats
        in_path, out_path = os.fspath(input_path), os.fspath(output_path)
        if os.path.exists(out_path):
            try:
                same = os.path.samefile(in_path, out_path)
            except OSError:
                same = False
            if same:
                raise ValueError(
                    f"input and output refer to the same file ({out_path!r}); "
                    "write to a different path, then move it into place"
                )
        stats = RedactionStats()
        chunks = read_chunks(in_path, self.chunk_size, encoding)
        with atomic_output(out_path, encoding=encoding) as out:
            for redacted in self.redact_stream(chunks, stats):
                out.write(redacted)
        return stats
