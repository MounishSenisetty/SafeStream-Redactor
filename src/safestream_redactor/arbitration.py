"""Conflict-only arbitration: a tier consulted only when detectors disagree.

Most spans are unambiguous — a well-formed email, a Luhn-valid card — and the
confidence/length policy in :func:`~safestream_redactor.entities.resolve_overlaps`
settles them without help. A minority are genuine *conflicts*:

- **overlap** — two tiers claim overlapping regions with near-equal confidence,
  so the tie-break is essentially a guess;
- **borderline** — a detection sits right at ``min_confidence``, where keep and
  drop are almost equally likely;
- **suppressed** — the contextual tier pushed a match below threshold that
  another tier is confident about.

Only those conflicts are handed to an :class:`Arbiter`. Restricting the arbiter
to disagreements keeps it rare, so a slow or costly one (an LLM) adds latency
only where it buys a better decision — everywhere else the deterministic policy
runs untouched.

Two arbiters ship:

- :class:`RuleArbiter` — deterministic and fully offline (the default). It reads
  only the candidates' own metadata, so it preserves the streaming/parallel
  equivalence guarantees and is what the tests pin.
- :class:`LLMArbiter` — delegates the ruling to any language-model client you
  inject (local or hosted); it is deliberately provider-neutral, taking a plain
  ``str -> str`` callable so the package hard-codes no vendor and pulls in no SDK.
  It sees only a bounded window around the conflict. Because a hosted call sends
  that window off the machine and a model's output is not bit-reproducible,
  enabling it **relaxes the offline guarantee and the equivalence theorems**
  (docs/FORMAL_MODEL.md §5); it is therefore opt-in and never the default. Inject
  a local model to keep the data on-machine.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from safestream_redactor.entities import Detection, EntityType

logger = logging.getLogger(__name__)

# How many characters of context on each side of a conflict the arbiter sees.
DEFAULT_WINDOW = 64
# Two candidates are "near-equal" (an overlap conflict), or a detection is "at
# the threshold" (a borderline conflict), when within this confidence margin.
DEFAULT_MARGIN = 0.15

# Coarse specificity ranking used as a deterministic tie-break: a specific,
# checkable label should beat a generic high-entropy or NER guess for the same
# text. Higher wins.
_GENERIC = frozenset({EntityType.SECRET, EntityType.CUSTOM})
_SOFT = frozenset({EntityType.PERSON, EntityType.ORG, EntityType.LOC})


def _specificity(det: Detection) -> int:
    if det.entity_type in _GENERIC:
        return 0
    if det.entity_type in _SOFT:
        return 1
    return 2  # structured PII and named credentials


@dataclass(slots=True)
class Conflict:
    """A cluster of overlapping/ambiguous candidates competing for one region.

    ``window`` is the text spanning ``[window_offset, window_offset + len(window))``
    — the region plus up to ``DEFAULT_WINDOW`` characters of real context on each
    side — so an arbiter can judge the span in situ. ``reason`` records why the
    cluster was flagged (``"overlap"`` / ``"borderline"`` / ``"suppressed"``).
    """

    start: int
    end: int
    candidates: list[Detection]
    window: str
    window_offset: int
    reason: str


@runtime_checkable
class Arbiter(Protocol):
    """Rules on one conflict: returns the winning candidate, or ``None`` to drop it."""

    def arbitrate(self, conflict: Conflict) -> Detection | None: ...


def _clusters(detections: Iterable[Detection]) -> list[list[Detection]]:
    """Group detections into maximal runs of mutually overlapping spans."""
    ordered = sorted(detections, key=lambda d: (d.start, d.end))
    groups: list[list[Detection]] = []
    current: list[Detection] = []
    reach = -1
    for det in ordered:
        if current and det.start < reach:
            current.append(det)
            reach = max(reach, det.end)
        else:
            if current:
                groups.append(current)
            current = [det]
            reach = det.end
    if current:
        groups.append(current)
    return groups


def _reason(cluster: list[Detection], min_confidence: float, margin: float) -> str | None:
    """Why this cluster is a conflict, or ``None`` if it is unambiguous."""
    if len(cluster) >= 2 and len({d.entity_type for d in cluster}) >= 2:
        confs = sorted((d.confidence for d in cluster), reverse=True)
        if confs[0] - confs[1] <= margin:
            return "overlap"
    top = max(cluster, key=lambda d: d.confidence)
    if abs(top.confidence - min_confidence) <= margin:
        return "borderline"
    if any(d.meta.get("context") == "suppressed" for d in cluster):
        return "suppressed"
    return None


def find_conflicts(
    detections: list[Detection],
    text: str,
    *,
    min_confidence: float,
    window: int = DEFAULT_WINDOW,
    margin: float = DEFAULT_MARGIN,
) -> list[Conflict]:
    """The subset of detection clusters that are genuinely ambiguous.

    Unambiguous clusters (a lone confident detection, well-separated types) are
    omitted, so the caller sends only real disagreements to an arbiter.
    """
    conflicts: list[Conflict] = []
    for cluster in _clusters(detections):
        reason = _reason(cluster, min_confidence, margin)
        if reason is None:
            continue
        start = min(d.start for d in cluster)
        end = max(d.end for d in cluster)
        w_start = max(0, start - window)
        w_end = min(len(text), end + window)
        conflicts.append(Conflict(start, end, list(cluster), text[w_start:w_end], w_start, reason))
    return conflicts


@dataclass(slots=True)
class RuleArbiter:
    """A deterministic, offline arbiter — the default.

    Picks the most defensible candidate without any model: a non-suppressed
    candidate beats a suppressed one, then higher confidence wins, then a more
    specific/checkable type, then the longer span. If the only survivor is a
    suppressed sub-threshold match, the region is dropped. Because it reads only
    the candidates' own fields, it is a pure function of local data and preserves
    the equivalence guarantees.
    """

    min_confidence: float = 0.5

    def arbitrate(self, conflict: Conflict) -> Detection | None:
        live = [d for d in conflict.candidates if d.meta.get("context") != "suppressed"]
        pool = live or conflict.candidates
        winner = max(pool, key=lambda d: (d.confidence, _specificity(d), d.end - d.start))
        if winner.meta.get("context") == "suppressed" and winner.confidence < self.min_confidence:
            return None
        winner.meta["arbiter"] = "rule"
        return winner


# A language-model client: prompt in, raw completion text out. Deliberately a
# bare callable so the package binds to no particular provider or SDK.
Client = Callable[[str], str]


def default_prompt(conflict: Conflict) -> str:
    """Build a compact, provider-neutral adjudication prompt for a conflict."""
    rel = conflict.start - conflict.window_offset
    rel_end = conflict.end - conflict.window_offset
    marked = (
        conflict.window[:rel] + "«" + conflict.window[rel:rel_end] + "»" + conflict.window[rel_end:]
    )
    lines = [
        "You are adjudicating a redaction conflict. Detectors disagree about the",
        "text marked with « » below. Decide which single candidate is the correct",
        "sensitive entity, or that none is.",
        "",
        f"Context: {marked!r}",
        "",
        "Candidates:",
    ]
    for i, det in enumerate(conflict.candidates):
        lines.append(f"  [{i}] type={det.entity_type.value} confidence={det.confidence:.2f}")
    lines += [
        "",
        "Answer with exactly one line:",
        "  KEEP <index>            (the candidate is correct as labelled)",
        "  KEEP <index> <type>     (correct span, but this SafeStream type)",
        "  DROP                    (none is a real sensitive entity)",
    ]
    return "\n".join(lines)


def _parse_ruling(response: str, conflict: Conflict) -> Detection | None:
    """Turn a client's reply into a kept detection, or ``None`` to drop.

    Unparseable replies fall back to keeping the strongest candidate — for a
    redactor a false positive is safer than a leaked false negative.
    """
    token = response.strip().splitlines()[0].strip() if response.strip() else ""
    parts = token.split()
    if parts and parts[0].upper() == "DROP":
        return None
    if len(parts) >= 2 and parts[0].upper() == "KEEP" and parts[1].isdigit():
        idx = int(parts[1])
        if 0 <= idx < len(conflict.candidates):
            winner = conflict.candidates[idx]
            if len(parts) >= 3:
                try:
                    winner.entity_type = EntityType.from_name(parts[2])
                except ValueError:
                    logger.warning("arbiter proposed unknown type %r; keeping label", parts[2])
            winner.meta["arbiter"] = "llm"
            return winner
    logger.warning("unparseable arbiter reply %r; keeping strongest candidate", token)
    winner = max(conflict.candidates, key=lambda d: d.confidence)
    winner.meta["arbiter"] = "llm-fallback"
    return winner


@dataclass(slots=True)
class LLMArbiter:
    """Delegates the ruling to any injected language-model ``client``.

    ``client`` is a plain ``str -> str`` callable (prompt in, completion out), so
    you can wire in a local model, a hosted API, or a stub in tests — the package
    itself names no provider. On a client error the conflict falls back to the
    deterministic :class:`RuleArbiter`, so a flaky model never crashes a run.

    Enabling this relaxes the offline and equivalence guarantees; see the module
    docstring.
    """

    client: Client
    build_prompt: Callable[[Conflict], str] = field(default=default_prompt)
    _fallback: RuleArbiter = field(default_factory=RuleArbiter)

    def arbitrate(self, conflict: Conflict) -> Detection | None:
        try:
            response = self.client(self.build_prompt(conflict))
        except Exception:
            logger.warning("arbiter client failed; using deterministic fallback", exc_info=True)
            return self._fallback.arbitrate(conflict)
        return _parse_ruling(response, conflict)
