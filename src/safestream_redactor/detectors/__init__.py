"""Detection tiers. Each detector exposes ``detect(text) -> list[Detection]``."""

from safestream_redactor.detectors.base import Detector
from safestream_redactor.detectors.contextual import ContextualScorer
from safestream_redactor.detectors.custom import CustomDetector
from safestream_redactor.detectors.deterministic import DeterministicDetector

__all__ = ["ContextualScorer", "CustomDetector", "Detector", "DeterministicDetector"]
