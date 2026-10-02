"""SafeStream-Redactor: streaming PII & credential redaction with constant memory usage."""

import logging

from safestream_redactor.calibration import Calibrator
from safestream_redactor.engine import WindowConfigurationError
from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.errors import MissingExtraError, OperatorError, SafeStreamError
from safestream_redactor.operators import Deanonymizer
from safestream_redactor.policy import RedactionMode, RedactionPolicy
from safestream_redactor.redactor import Redactor
from safestream_redactor.report import RedactionStats

__version__ = "0.4.0"

# Standard library-package practice: emit nothing unless the embedding
# application configures logging. Detection content is never logged anywhere.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "Calibrator",
    "Deanonymizer",
    "Detection",
    "EntityType",
    "MissingExtraError",
    "OperatorError",
    "RedactionMode",
    "RedactionPolicy",
    "RedactionStats",
    "Redactor",
    "SafeStreamError",
    "WindowConfigurationError",
    "__version__",
]
