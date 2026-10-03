"""Lookaround-free equivalents of the tier-1 patterns that use lookaround.

Why this exists
---------------

The deterministic tier's throughput-dominating PII patterns (SSN, credit card,
IPv4, IPv6, phone) and three credential patterns (AWS secret, Anthropic, OpenAI)
use lookahead/lookbehind assertions (``(?<!…)`` / ``(?!…)``). No finite-automaton
engine — Rust's ``regex`` crate, RE2, Hyperscan/Vectorscan — supports lookaround.
So a native, single-pass detection core (see ``docs/PERF_ASSESSMENT.md``) cannot
use these patterns as written. Before any native core can be byte-identical to the
Python tier, the patterns must be re-expressed as a **lookaround-free candidate
regex + a code-level boundary validator**.

This module is that re-expression, plus the exact validator logic, kept in pure
Python so it can be:

1. proven byte-identical to :class:`DeterministicDetector` (``tests/test_lookaround_free.py``),
2. ported directly into the native core (the candidate regexes are DFA-compatible;
   the boundary/validator logic is a line-for-line spec).

Scope and honesty
-----------------

Seven patterns convert cleanly (a lookaround-free candidate + a boundary check
reproduces ``re.finditer`` byte-for-byte): ``ssn``, ``ipv4``, ``ipv6``,
``mac_address``, ``aws_secret``, ``anthropic_key``, ``openai_key``. Their equivalence is a required
gate in the test module.

**``credit_card`` and ``phone`` are deliberately NOT here.** Their cores are
greedy and variable-length over an alphabet that includes separators, so a
negative lookahead triggers regex backtracking that a candidate + post-filter
cannot reproduce (measured: the naive conversion diverges). They need a dedicated
streaming state-machine scanner in the native core — the algorithm is specified in
``docs/NATIVE_CORE.md``. Real-world scanners hand-code card/phone for the same
reason; forcing them into a lookaround-free regex here would risk under-detection,
the exact failure mode that disqualified the re2 backend
(``docs/PERFORMANCE_BACKENDS.md``).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from safestream_redactor.detectors.deterministic import ipv4_ok, ipv6_ok, ssn_ok
from safestream_redactor.entities import Detection, EntityType

# Boundary checks must reproduce the ORIGINAL assertion character classes with the
# EXACT same semantics — critically, Python's ``\d`` and ``\w`` are *Unicode-aware*
# (an Arabic-Indic digit ``٩`` is a ``\d``), so ASCII string membership would
# diverge (and under-restrict) on non-ASCII input — the same Unicode trap that
# disqualified re2. So each removed assertion is re-expressed as a compiled
# one-character class matching the original exactly. A native port uses its
# engine's Unicode classes (Rust's ``regex`` matches Python here).
_C_DIGIT_DASH = re.compile(r"[\d-]")  # ssn (?<![\d-]) / (?![\d-])
_C_DIGIT_DOT = re.compile(r"[\d.]")  # ipv4 (?<![\d.])
_C_DIGIT = re.compile(r"\d")  # ipv4 (?!\d) / (?!\.\d)
_C_WORD_COLON_DOT = re.compile(r"[\w:.]")  # ipv6 (?<![\w:.])
_C_WORD_COLON = re.compile(r"[\w:]")  # ipv6 (?![\w:])
_C_AWS = re.compile(r"[A-Za-z0-9/+]")  # aws (?![A-Za-z0-9/+]) — ASCII by design
_C_WORD_COLON_DOT_DASH = re.compile(r"[\w:.-]")  # mac (?<![\w:.-])
_C_WORD_COLON_DASH = re.compile(r"[\w:-]")  # mac (?![\w:-])


def _before_ok(text: str, start: int, cls: re.Pattern[str]) -> bool:
    """Reproduce ``(?<!cls)`` — start-of-text always passes."""
    return start == 0 or cls.match(text[start - 1]) is None


def _after_ok(text: str, end: int, cls: re.Pattern[str]) -> bool:
    """Reproduce ``(?!cls)`` — end-of-text always passes."""
    return end == len(text) or cls.match(text[end]) is None


def _ipv4_after_ok(text: str, end: int) -> bool:
    """Reproduce IPv4's ``(?!\\d)(?!\\.\\d)`` two-character lookahead (Unicode ``\\d``)."""
    if end == len(text):
        return True
    ch = text[end]
    if _C_DIGIT.match(ch) is not None:
        return False
    return not (ch == "." and end + 1 < len(text) and _C_DIGIT.match(text[end + 1]) is not None)


# --- lookaround-free pattern spec --------------------------------------------


@dataclass(frozen=True, slots=True)
class LFPattern:
    """A lookaround-free candidate + boundary validator for one entity type.

    ``candidate`` carries no lookaround (only DFA-compatible constructs, incl.
    ``\\b`` which every target engine supports). ``group`` is the capture whose
    span is emitted. ``boundary`` re-checks the removed assertions in code;
    ``value_ok`` is the existing semantic validator (Luhn, octet range, …).
    """

    entity_type: EntityType
    candidate: re.Pattern[str]
    confidence: float
    group: int = 0
    boundary: Callable[[str, int, int], bool] | None = None
    value_ok: Callable[[str], bool] | None = None
    anchors: tuple[str, ...] = ()
    anchors_lower: tuple[str, ...] = ()
    needs_digit: bool = False


def _ssn_boundary(text: str, s: int, e: int) -> bool:
    return _before_ok(text, s, _C_DIGIT_DASH) and _after_ok(text, e, _C_DIGIT_DASH)


def _ipv4_boundary(text: str, s: int, e: int) -> bool:
    return _before_ok(text, s, _C_DIGIT_DOT) and _ipv4_after_ok(text, e)


def _ipv6_boundary(text: str, s: int, e: int) -> bool:
    return _before_ok(text, s, _C_WORD_COLON_DOT) and _after_ok(text, e, _C_WORD_COLON)


def _mac_boundary(text: str, s: int, e: int) -> bool:
    return _before_ok(text, s, _C_WORD_COLON_DOT_DASH) and _after_ok(text, e, _C_WORD_COLON_DASH)


def _mac_value_ok(value: str) -> bool:
    # the ``([:-])…\1`` backreference: one separator throughout, 6..20 groups.
    # A mixed or over-long run fails here exactly where the original fails: every
    # shorter prefix ends before a separator, which its lookahead rejects.
    return (":" in value) != ("-" in value) and 6 <= (len(value) + 1) // 3 <= 20


def _aws_after_ok(text: str, s: int, e: int) -> bool:
    # (?![A-Za-z0-9/+]) on the captured 40-char value
    return _after_ok(text, e, _C_AWS)


LF_PATTERNS: tuple[LFPattern, ...] = (
    LFPattern(
        EntityType.SSN,
        re.compile(r"\d{3}-\d{2}-\d{4}"),
        0.85,
        boundary=_ssn_boundary,
        value_ok=ssn_ok,
        needs_digit=True,
    ),
    LFPattern(
        EntityType.IPV4,
        re.compile(r"\d{1,3}(?:\.\d{1,3}){3}"),
        0.9,
        boundary=_ipv4_boundary,
        value_ok=ipv4_ok,
        needs_digit=True,
    ),
    LFPattern(
        EntityType.IPV6,
        re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"),
        0.9,
        boundary=_ipv6_boundary,
        value_ok=ipv6_ok,
        anchors=(":",),
    ),
    # MAC: lookarounds and the separator backreference re-checked in code
    LFPattern(
        EntityType.MAC_ADDRESS,
        re.compile(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2})+"),
        0.85,
        boundary=_mac_boundary,
        value_ok=_mac_value_ok,
        anchors=(":", "-"),
    ),
    # AWS secret: label-anchored; lookahead removed and re-checked on the value.
    LFPattern(
        EntityType.AWS_SECRET,
        re.compile(
            r"(?i)aws[_\s-]*secret[_\s-]*(?:access[_\s-]*)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})"
        ),
        0.9,
        group=1,
        boundary=_aws_after_ok,
        anchors_lower=("aws",),
    ),
    # Anthropic/OpenAI: the (?<=[A-Za-z0-9_]) lookbehind (last char must be a word
    # char, i.e. not a trailing '-') is folded INTO the regex as
    # ``[A-Za-z0-9_-]{19,}[A-Za-z0-9_]`` (>=19 class chars + a final word char =
    # >=20 with a word-char end). This is lookaround-free and DFA-compatible, and
    # lets the engine do the backtracking the original did. \b is kept (supported).
    LFPattern(
        EntityType.ANTHROPIC_KEY,
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{19,}[A-Za-z0-9_]\b"),
        0.98,
        anchors=("sk-ant-",),
    ),
    LFPattern(
        EntityType.OPENAI_KEY,
        re.compile(
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{19,}[A-Za-z0-9_]|[A-Za-z0-9]{32,})\b"
        ),
        0.95,
        anchors=("sk-",),
    ),
)

# entity types this module covers (the rest of tier 1 has no lookaround and is
# already DFA-ready as written; credit_card/phone need a scanner — see docstring)
COVERED: frozenset[EntityType] = frozenset(p.entity_type for p in LF_PATTERNS)

_DIGIT = re.compile(r"\d")


@dataclass(slots=True)
class LookaroundFreeDetector:
    """Runs the lookaround-free specs; byte-identical to the originals for COVERED.

    This is a reference/validation implementation and the spec the native core
    ports. It is not wired into the default pipeline.
    """

    name: str = "lookaround-free"
    prefilter: bool = True
    patterns: tuple[LFPattern, ...] = field(default=LF_PATTERNS)

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        has_digit: bool | None = None
        lowered: str | None = None
        for pat in self.patterns:
            if self.prefilter:
                if pat.needs_digit:
                    if has_digit is None:
                        has_digit = _DIGIT.search(text) is not None
                    if not has_digit:
                        continue
                if pat.anchors and not any(a in text for a in pat.anchors):
                    continue
                if pat.anchors_lower:
                    if lowered is None:
                        lowered = text.lower()
                    if not any(a in lowered for a in pat.anchors_lower):
                        continue
            for m in pat.candidate.finditer(text):
                s, e = m.start(pat.group), m.end(pat.group)
                matched = m.group(pat.group)
                if pat.boundary is not None and not pat.boundary(text, s, e):
                    continue
                if pat.value_ok is not None and not pat.value_ok(matched):
                    continue
                found.append(
                    Detection(
                        start=s,
                        end=e,
                        text=matched,
                        entity_type=pat.entity_type,
                        confidence=pat.confidence,
                        source=self.name,
                    )
                )
        return found
