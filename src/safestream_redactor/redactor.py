"""The main user-facing API: the :class:`Redactor`."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator

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
    extra_detectors:
        Any additional objects implementing the :class:`Detector` protocol.
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
        extra_detectors: Iterable[Detector] = (),
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
        # contextual tier also contributes trigger-gated detections of its own
        if resolved_types is None or EntityType.SSN in resolved_types:
            self._detectors.append(self._scorer)

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[Detection]:
        """All detections in ``text``, scored, filtered, and non-overlapping."""
        raw: list[Detection] = []
        for detector in self._detectors:
            raw.extend(detector.detect(text))
        self._scorer.adjust(text, raw)
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

    def redact_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Redact an iterable/generator of text chunks, yielding redacted chunks.

        Memory stays bounded by ``chunk_size + overlap`` regardless of total
        input size. Entities up to ``overlap`` characters long are detected
        even when split across chunk boundaries.
        """
        return stream_transform(chunks, self.detect, self.policy.apply, self.overlap)

    def redact_file(
        self,
        input_path: str | os.PathLike[str],
        output_path: str | os.PathLike[str],
        encoding: str = "utf-8",
    ) -> None:
        """Redact ``input_path`` into ``output_path`` without loading either fully."""
        chunks = read_chunks(os.fspath(input_path), self.chunk_size, encoding)
        with open(output_path, "w", encoding=encoding) as out:
            for redacted in self.redact_stream(chunks):
                out.write(redacted)
