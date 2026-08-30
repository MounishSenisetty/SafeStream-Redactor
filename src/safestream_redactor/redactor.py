"""The main user-facing API: the :class:`Redactor`."""

from __future__ import annotations

import contextlib
import logging
import os
import stat
import tempfile
from collections.abc import Iterable, Iterator

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


def _match_destination_mode(tmp_path: str, out_path: str) -> None:
    """Give the temp file the permissions the destination would have had.

    ``mkstemp`` creates 0o600 files; a plain ``open(out, "w")`` would instead
    keep an existing file's mode, or apply the process umask to a new one.
    Matching that keeps atomic replacement behaviourally identical to the
    direct write it replaced.
    """
    try:
        mode = stat.S_IMODE(os.stat(out_path).st_mode)
    except OSError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    with contextlib.suppress(OSError):
        os.chmod(tmp_path, mode)


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
        ``safestream_redactor.detectors`` entry-point group (on by default).
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
        use_entropy: bool = True,
        calibrator: Calibrator | None = None,
        extra_detectors: Iterable[Detector] = (),
        load_plugins: bool = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = DEFAULT_OVERLAP,
    ) -> None:
        resolved_types = (
            None
            if types is None
            else [t if isinstance(t, EntityType) else EntityType.from_name(t) for t in types]
        )
        self.policy = policy or RedactionPolicy()
        self.min_confidence = min_confidence
        self.calibrator = calibrator
        self.chunk_size = chunk_size
        self.overlap = overlap
        self._scorer = ContextualScorer()

        self._detectors: list[Detector] = [DeterministicDetector(resolved_types)]
        custom_words = list(custom_words)
        custom_patterns = list(custom_patterns)
        if custom_words or custom_patterns:
            self._detectors.append(CustomDetector(custom_words, custom_patterns))
        if use_ner:
            from safestream_redactor.detectors.ner import NERDetector

            self._detectors.append(NERDetector(ner_model))
        # statistical tier: generic high-entropy secrets (on by default)
        if use_entropy and (resolved_types is None or EntityType.SECRET in resolved_types):
            from safestream_redactor.detectors.entropy import EntropyDetector

            self._detectors.append(EntropyDetector())
        self._detectors.extend(extra_detectors)
        # third-party detectors registered via entry points
        if load_plugins:
            from safestream_redactor.detectors.registry import load_plugins as _load_plugins

            self._detectors.extend(_load_plugins())
        # contextual tier also contributes trigger-gated detections of its own
        if resolved_types is None or EntityType.SSN in resolved_types:
            self._detectors.append(self._scorer)
        logger.debug("detector tiers active: %s", [d.name for d in self._detectors])

        # Boundary-correctness guard: the overlap must cover the longest span any
        # active detector can emit (plus the context it reads), or an entity that
        # straddles a chunk boundary could be silently missed — a fail-open
        # coverage loss. The default overlap already satisfies the built-in tiers;
        # this warns only when a caller shrinks it below what the detectors need.
        needed = self.min_safe_overlap
        if self.overlap < needed:
            logger.warning(
                "overlap=%d is below the %d characters the active detectors require "
                "(%s); entities longer than the overlap that straddle a chunk boundary "
                "may be missed",
                self.overlap,
                needed,
                ", ".join(sorted({d.name for d in self._detectors})),
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

    def detect_stream(self, chunks: Iterable[str]) -> Iterator[tuple[str, list[Detection]]]:
        """Stream detection without redacting.

        Yields ``(segment, detections)`` pairs; segments concatenate to the
        full input, and each detection's offsets are relative to its segment.
        """
        return stream_windows(chunks, self.detect, self.overlap)

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
            return stream_transform(chunks, self.detect, self.policy.apply, self.overlap)
        return self._redact_stream_with_stats(chunks, stats)

    def _redact_stream_with_stats(
        self, chunks: Iterable[str], stats: RedactionStats
    ) -> Iterator[str]:
        for segment, detections in stream_windows(chunks, self.detect, self.overlap):
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
        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(out_path) or ".",
            prefix=os.path.basename(out_path) + ".",
            suffix=".tmp",
        )
        try:
            with open(fd, "w", encoding=encoding) as out:
                for redacted in self.redact_stream(chunks, stats):
                    out.write(redacted)
            _match_destination_mode(tmp_path, out_path)
            os.replace(tmp_path, out_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        return stats
