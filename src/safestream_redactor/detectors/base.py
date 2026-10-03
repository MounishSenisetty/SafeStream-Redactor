"""Detector interface. Implement this Protocol to plug a new tier in.

Streaming requirements
----------------------

A detector may also declare :class:`StreamingRequirements`, telling the engine
how much context it needs to stay correct across chunk boundaries. The engine
uses these declarations to size its overlap window instead of relying on a
single global constant: the required overlap is the largest span any active
detector can emit (plus the context it needs), computed by
:func:`safestream_redactor.engine.required_overlap`. A detector that omits the
attribute is treated with a conservative default (see :func:`requirements_of`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from safestream_redactor.entities import Detection


@dataclass(frozen=True, slots=True)
class StreamingRequirements:
    """How much context a detector needs to be correct across chunk boundaries.

    Attributes
    ----------
    max_span:
        The longest detection span (in characters) the detector can emit. This
        is the value that drives the engine's overlap: an entity up to this long
        is guaranteed to be seen whole even when split by a chunk boundary
        (``docs/FORMAL_MODEL.md``, Theorem 1 requires ``overlap >= max_span``).
    left_context:
        Characters *before* a candidate the detector reads to make its decision
        (e.g. the contextual scorer's trigger-word window). The engine already
        carries emitted text as read-only left context; this documents the
        minimum it must preserve.
    right_context:
        Characters *after* a candidate the detector reads before deciding. Added
        to ``max_span`` when sizing the overlap so the trailing context is still
        buffered when the candidate is scored.
    stateful:
        **Advisory only; nothing enforces it.** True if the detector carries state
        across ``detect`` calls. The built-in tiers are all stateless (each ``detect``
        call is a pure function of its input window), which is what makes the
        streaming/parallel equivalence proof hold; a stateful detector must document
        its own guarantees. The flag is surfaced by the MCP ``detectors`` tool.
    streaming_safe:
        False if the detector cannot be run on windows at all (it needs the whole
        input). **Enforced:** :class:`~safestream_redactor.redactor.Redactor` raises
        :class:`~safestream_redactor.engine.WindowConfigurationError` at construction
        for such a detector, because every entry point but ``redact`` is windowed.
        None of the built-ins set this.
    """

    max_span: int
    left_context: int = 0
    right_context: int = 0
    stateful: bool = False
    streaming_safe: bool = True

    @property
    def required_overlap(self) -> int:
        """Minimum engine overlap for this detector to be boundary-correct."""
        return max(self.max_span + self.right_context, self.left_context)


# Conservative fallback for a detector that declares nothing: assume it can emit
# a span up to the historical default overlap. This preserves the old behaviour
# exactly for third-party detectors written before this attribute existed.
_DEFAULT_REQUIREMENTS = StreamingRequirements(max_span=8 * 1024)


@runtime_checkable
class Detector(Protocol):
    """Anything with a name and a ``detect`` method is a detector.

    A detector may optionally expose a ``requirements`` :class:`StreamingRequirements`.
    """

    name: str

    def detect(self, text: str) -> list[Detection]: ...


def requirements_of(detector: object) -> StreamingRequirements:
    """Return a detector's declared :class:`StreamingRequirements`, or the default.

    Detectors written before this attribute existed (or third-party ones that
    omit it) get :data:`_DEFAULT_REQUIREMENTS`, so the engine keeps its previous
    overlap behaviour for them.
    """
    req = getattr(detector, "requirements", None)
    return req if isinstance(req, StreamingRequirements) else _DEFAULT_REQUIREMENTS


# --- placeholders: a reference or a mask is never the sensitive value ----------

_PLACEHOLDER = re.compile(
    r"(?i)\A(?:"
    r"|null|none|nil|undefined|n/?a|-+|\.+|_+|\*+|x+|#+"  # empty, masks, rulers
    r"|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%"  # ${VAR} $VAR %VAR%
    r"|\{\{[^}]*\}\}|\{[A-Za-z_][A-Za-z0-9_.]*\}"  # {{ var }} {var}
    r"|<[^>]*>|\[[^\]]*redacted[^\]]*\]|redacted|masked"
    r"|(?:os\.environ|process\.env|env)[\[.(].*|(?:os\.)?getenv\(.*\)"
    r")\Z"
)


def is_placeholder(value: str) -> bool:
    """True for empty values, masks and references to a value stored elsewhere."""
    return bool(_PLACEHOLDER.match(value.strip().strip("\"'")))
