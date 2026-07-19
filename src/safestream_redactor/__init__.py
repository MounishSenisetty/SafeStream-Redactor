"""SafeStream-Redactor: streaming PII & credential redaction with constant memory usage."""

from safestream_redactor.entities import Detection, EntityType
from safestream_redactor.policy import RedactionMode, RedactionPolicy
from safestream_redactor.redactor import Redactor

__version__ = "0.1.0"

__all__ = [
    "Detection",
    "EntityType",
    "RedactionMode",
    "RedactionPolicy",
    "Redactor",
    "__version__",
]
