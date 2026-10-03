"""The main user-facing API: the :class:`Redactor`."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Iterator

from safestream_redactor._atomic import atomic_output
from safestream_redactor.calibration import Calibrator
from safestream_redactor.detectors.base import Detector, requirements_of
from safestream_redactor.detectors.contextual import ContextualScorer
from safestream_redactor.detectors.custom import CustomDetector
from safestream_redactor.detectors.deterministic import DeterministicDetector
from safestream_redactor.engine import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP,
    WindowConfigurationError,
    WindowObserver,
    read_chunks,
    stream_transform,
    stream_windows,
)
from safestream_redactor.entities import Detection, EntityType, resolve_overlaps
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.report import RedactionStats

logger = logging.getLogger(__name__)

# entity types produced only by the opt-in regional tier
REGIONAL_TYPES = frozenset(
    {
        EntityType.IBAN,
        EntityType.CRYPTO_ADDRESS,
        EntityType.UK_NINO,
        EntityType.NHS_NUMBER,
        EntityType.IN_AADHAAR,
        EntityType.IN_PAN,
    }
)


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
        Enable the optional spaCy tier (requires the ``ner`` extra).
    use_onnx:
        Enable the optional local ONNX NER tier (PERSON/ORG/LOC via an on-device
        ONNX model, no data egress; requires the ``onnx`` extra). Needs
        ``onnx_model`` and ``onnx_vocab``; ``onnx_labels`` (id->tag JSON) is
        optional and defaults to the CoNLL IOB2 scheme.
    use_entropy:
        Enable the statistical tier that flags high-entropy secrets with no
        published format (on by default).
    use_regional:
        Enable the regional tier (IBAN, crypto addresses, UK NINO/NHS, India
        Aadhaar/PAN; ``detectors/regional.py``). Off by default because it changes
        what existing deployments redact; naming one of its types in ``types``
        also enables it.
    use_dates:
        Enable the date/time tier (``EntityType.DATE``). Off by default because
        logs carry a timestamp on every line; naming ``date`` in ``types`` also
        enables it.
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
        use_ner: bool = False,
        ner_model: str = "en_core_web_sm",
        use_gazetteer: bool = False,
        use_ensemble: bool = False,
        semantic_policy: str = "strict",
        use_onnx: bool = False,
        onnx_model: str | None = None,
        onnx_vocab: str | dict[str, int] | None = None,
        onnx_labels: str | dict[int | str, str] | None = None,
        onnx_min_score: float = 0.35,
        onnx_batch_size: int = 1,
        use_entropy: bool = True,
        use_regional: bool = False,
        use_dates: bool = False,
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
        self.allow_unsafe_overlap = allow_unsafe_overlap
        self._scorer = ContextualScorer(backend=backend)

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
            self._detectors.append(LabeledIdentifierDetector(backend=backend))
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
                    onnx_model,
                    onnx_vocab,
                    onnx_labels,
                    min_score=onnx_min_score,
                    batch_size=onnx_batch_size,
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

            self._detectors.append(EntropyDetector(backend=backend))
            self._detectors.append(CompoundSecretDetector(backend=backend))
        from safestream_redactor.detectors.regional import RegionalDetector

        if use_regional or (resolved_types is not None and REGIONAL_TYPES & set(resolved_types)):
            self._detectors.append(RegionalDetector())
        if use_dates or (resolved_types is not None and EntityType.DATE in resolved_types):
            from safestream_redactor.detectors.deterministic import DateDetector

            self._detectors.append(DateDetector())
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

        self._reject_non_streaming_detectors()
        self.enforce_overlap_safety(allow_unsafe_overlap)

    def _reject_non_streaming_detectors(self) -> None:
        """Fail closed on a tier that declares it cannot run on windows.

        Every entry point except :meth:`redact` feeds detectors bounded windows, so a
        detector with ``streaming_safe=False`` (it needs the whole input) would be run
        on text it cannot see in full and silently miss what straddles a boundary. The
        flag used to be documented as disabling streaming but nothing read it; now a
        declaration is a promise the constructor keeps.
        """
        unsafe = [d.name for d in self._detectors if not requirements_of(d).streaming_safe]
        if unsafe:
            raise WindowConfigurationError(
                f"detector(s) {', '.join(unsafe)} declare streaming_safe=False: they need the "
                "whole input and cannot run on the bounded windows the streaming, file and "
                "parallel engines use, so they would miss entities across window boundaries"
            )

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
        self.allow_unsafe_overlap = allow_unsafe
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
        raise WindowConfigurationError(
            f"overlap={self.overlap} is below the {needed}-character safe minimum "
            f"required by the active detectors ({names}). At a smaller overlap an "
            "entity that straddles a chunk boundary can be missed and streaming "
            "output can diverge from a whole-document pass (a redaction leak). "
            f"Raise overlap to at least {needed}, or pass allow_unsafe_overlap=True "
            "(--insecure-allow-leak-prone-overlap) to override (not recommended for redaction)."
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
        return resolve_overlaps(confident)

    # ------------------------------------------------------------------
    # redaction
    # ------------------------------------------------------------------

    def redact(self, text: str) -> str:
        """Redact a string held fully in memory."""
        return self.policy.apply(text, self.detect(text))

    def detect_stream(
        self, chunks: Iterable[str], *, on_window: WindowObserver | None = None
    ) -> Iterator[tuple[str, list[Detection]]]:
        """Stream detection without redacting.

        Yields ``(segment, detections)`` pairs; segments concatenate to the
        full input, and each detection's offsets are relative to its segment.
        ``on_window`` observes every detection pass (see
        :class:`~safestream_redactor.engine.WindowTrace`).
        """
        return stream_windows(
            chunks,
            self.detect,
            self.overlap,
            min_emit=self.chunk_size,
            on_window=on_window,
            strict_spans=not self.allow_unsafe_overlap,
        )

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
                chunks,
                self.detect,
                self.policy.apply,
                self.overlap,
                min_emit=self.chunk_size,
                strict_spans=not self.allow_unsafe_overlap,
            )
        return self._redact_stream_with_stats(chunks, stats)

    def _redact_stream_with_stats(
        self, chunks: Iterable[str], stats: RedactionStats
    ) -> Iterator[str]:
        for segment, detections in stream_windows(
            chunks,
            self.detect,
            self.overlap,
            min_emit=self.chunk_size,
            strict_spans=not self.allow_unsafe_overlap,
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
