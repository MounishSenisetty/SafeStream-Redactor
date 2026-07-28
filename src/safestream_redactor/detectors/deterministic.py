"""Tier 1: regex patterns plus validation functions.

Every pattern is paired with an optional validator so that a syntactic match
alone is not enough — e.g. credit cards must pass the Luhn checksum and IPv6
candidates must parse with :mod:`ipaddress`.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from safestream_redactor.entities import Detection, EntityType

# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------


def luhn_ok(number: str) -> bool:
    """Luhn checksum used by all major card networks."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ssn_ok(match_text: str) -> bool:
    """Reject SSNs with impossible area/group/serial numbers."""
    area, group, serial = re.split(r"[-\s]", match_text)
    if area in {"000", "666"} or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


# shapes that a naive phone regex swallows but which are never phone numbers
_DATE_SHAPE = re.compile(r"\A(?:19|20)\d{2}-\d{2}-\d{2}\Z")  # ISO date
_SSN_SHAPE = re.compile(r"\A\d{3}-\d{2}-\d{4}\Z")  # SSN grouping


def phone_ok(match_text: str) -> bool:
    stripped = match_text.strip()
    if _DATE_SHAPE.match(stripped) or _SSN_SHAPE.match(stripped):
        return False
    digits = re.sub(r"\D", "", match_text)
    return 7 <= len(digits) <= 15


def ipv6_ok(match_text: str) -> bool:
    try:
        ipaddress.IPv6Address(match_text.split("%")[0])
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pattern:
    entity_type: EntityType
    regex: re.Pattern[str]
    confidence: float
    validator: Callable[[str], bool] | None = None
    group: int = 0  # capture group whose span becomes the detection
    # Prefilter: every possible match of ``regex`` is guaranteed to contain at
    # least one of these literals, so when none occur in a window the regex is
    # skipped entirely. A C-level substring scan is orders of magnitude cheaper
    # than the regex pass it avoids; on secret-sparse text most patterns never
    # run. Empty tuples mean "always run".
    anchors: tuple[str, ...] = ()  # case-sensitive, checked against the raw text
    anchors_lower: tuple[str, ...] = ()  # checked against text.lower()
    needs_digit: bool = False  # every match contains at least one ASCII digit


_DIGIT = re.compile(r"\d")


_PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        EntityType.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
        anchors=("@",),
    ),
    Pattern(
        EntityType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"[A-Za-z0-9+/=\s]+?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        0.99,
        anchors=("-----BEGIN",),
    ),
    Pattern(
        EntityType.JWT,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        0.95,
        anchors=("eyJ",),
    ),
    Pattern(
        EntityType.AWS_KEY,
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        0.98,
        anchors=("AKIA", "ASIA", "ABIA", "ACCA"),
    ),
    Pattern(
        EntityType.GITHUB_TOKEN,
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        0.98,
        anchors=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    ),
    Pattern(
        EntityType.SLACK_TOKEN,
        re.compile(r"\bxox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48}){0,3}\b"),
        0.98,
        anchors=("xox",),
    ),
    Pattern(
        EntityType.SLACK_WEBHOOK,
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{16,}"
        ),
        0.98,
        anchors=("hooks.slack.com",),
    ),
    Pattern(
        EntityType.STRIPE_KEY,
        re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b"),
        0.97,
        anchors=("k_live_", "k_test_"),
    ),
    Pattern(
        EntityType.GOOGLE_API_KEY,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        0.95,
        anchors=("AIza",),
    ),
    Pattern(
        EntityType.SENDGRID_KEY,
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        0.98,
        anchors=("SG.",),
    ),
    Pattern(
        EntityType.TWILIO_KEY,
        re.compile(r"\bSK[0-9a-f]{32}\b"),
        0.9,
        anchors=("SK",),
    ),
    Pattern(
        EntityType.NPM_TOKEN,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        0.98,
        anchors=("npm_",),
    ),
    Pattern(
        EntityType.ANTHROPIC_KEY,
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}(?<=[A-Za-z0-9_])\b"),
        0.98,
        anchors=("sk-ant-",),
    ),
    # legacy 48-char keys and the newer sk-proj-/sk-svcacct-/sk-admin- forms;
    # sk-ant- is Anthropic's prefix and Stripe uses sk_live_/sk_test_ (underscore),
    # so neither collides with this pattern.
    Pattern(
        EntityType.OPENAI_KEY,
        re.compile(
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}(?<=[A-Za-z0-9_])"
            r"|[A-Za-z0-9]{32,})\b"
        ),
        0.95,
        anchors=("sk-",),
    ),
    # password inside a URL's userinfo section (postgres://user:PASS@host, ...);
    # only the password is the detection, so the rest of the URL stays readable.
    # Scored above the email pattern so the inevitable "PASS@host.tld" email
    # overlap resolves to this more precise label.
    Pattern(
        EntityType.URL_CREDENTIALS,
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:([^\s@/]{1,128})@[^\s@]"),
        0.97,
        group=1,
        anchors=("://",),
    ),
    Pattern(
        EntityType.API_KEY,
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token"
            r"|token|password|passwd|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{12,128})[\"']?"
        ),
        0.75,
        group=1,
        anchors_lower=("key", "secret", "token", "pass", "pwd"),
    ),
    Pattern(
        EntityType.CREDIT_CARD,
        re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        0.9,
        validator=luhn_ok,
        needs_digit=True,
    ),
    Pattern(
        EntityType.SSN,
        re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"),
        0.85,
        validator=ssn_ok,
        needs_digit=True,
    ),
    Pattern(
        EntityType.IPV4,
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
        ),
        0.9,
        needs_digit=True,
    ),
    Pattern(
        EntityType.IPV6,
        # loose candidate (hex groups separated by >=2 colons); ipaddress validates
        re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])"),
        0.9,
        validator=ipv6_ok,
        anchors=(":",),
    ),
    # structured phone: a leading + country code or a (area code) is a strong
    # signal, so this scores high enough to stand on its own.
    Pattern(
        EntityType.PHONE,
        re.compile(
            r"(?<![\w.-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{1,4}\)[ .-]?)"
            r"\d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w-])(?!\.\d)"
        ),
        0.6,
        validator=phone_ok,
        needs_digit=True,
    ),
    # bare phone: separated digit groups with no + or parens are ambiguous with
    # dates/ids, so this scores below the default threshold and only survives
    # when the contextual tier finds a nearby phone cue ("call", "tel", ...).
    Pattern(
        EntityType.PHONE,
        re.compile(r"(?<![\w.+(-])\d{2,4}(?:[ .-]\d{2,4}){2,4}(?![\w-])(?!\.\d)"),
        0.45,
        validator=phone_ok,
        needs_digit=True,
    ),
)


class DeterministicDetector:
    """Runs the built-in regex+validator patterns, optionally a subset of types.

    Patterns are prefiltered per call: a regex only runs when the text contains
    one of its guaranteed anchor literals (or a digit, for numeric patterns),
    which skips most of the pattern set on secret-sparse text. Prefiltering is
    an optimisation only — output is identical with it disabled
    (``prefilter=False``), and a differential test enforces that.
    """

    name = "deterministic"

    def __init__(
        self, types: Iterable[EntityType] | None = None, *, prefilter: bool = True
    ) -> None:
        wanted = set(types) if types is not None else None
        self._patterns = [p for p in _PATTERNS if wanted is None or p.entity_type in wanted]
        self._prefilter = prefilter

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        lowered: str | None = None
        has_digit: bool | None = None
        for pattern in self._patterns:
            if self._prefilter:
                if pattern.needs_digit:
                    if has_digit is None:
                        has_digit = _DIGIT.search(text) is not None
                    if not has_digit:
                        continue
                if pattern.anchors and not any(a in text for a in pattern.anchors):
                    continue
                if pattern.anchors_lower:
                    if lowered is None:
                        lowered = text.lower()
                    low = lowered
                    if not any(a in low for a in pattern.anchors_lower):
                        continue
            for m in pattern.regex.finditer(text):
                matched = m.group(pattern.group)
                if pattern.validator is not None and not pattern.validator(matched):
                    continue
                found.append(
                    Detection(
                        start=m.start(pattern.group),
                        end=m.end(pattern.group),
                        text=matched,
                        entity_type=pattern.entity_type,
                        confidence=pattern.confidence,
                        source=self.name,
                    )
                )
        return found
