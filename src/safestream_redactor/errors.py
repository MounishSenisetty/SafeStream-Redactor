"""One root for SafeStream's own failures.

Catch :class:`SafeStreamError` to handle everything the library raises on purpose;
the subclasses also inherit the builtin they historically were (``ValueError``,
``ImportError``), so existing ``except ValueError`` / ``except ImportError``
handlers keep working.
"""

from __future__ import annotations


class SafeStreamError(Exception):
    """Base class for errors SafeStream raises deliberately."""


class MissingExtraError(SafeStreamError, ImportError):
    """An optional dependency a feature needs is not installed.

    Distinct from a configuration or data error so a missing library can never be
    mistaken for, say, a wrong key.
    """

    def __init__(self, feature: str, extra: str) -> None:
        self.extra = extra
        super().__init__(
            f"{feature} needs an optional dependency: pip install 'safestream-redactor[{extra}]'"
        )


class OperatorError(SafeStreamError, ValueError):
    """A redaction operator cannot handle the value it was given."""
