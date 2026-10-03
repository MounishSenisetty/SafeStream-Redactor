"""Tier 1: regex patterns plus validation functions.

Every pattern is paired with an optional validator so that a syntactic match
alone is not enough — e.g. credit cards must pass the Luhn checksum and IPv6
candidates must parse with :mod:`ipaddress`.
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from safestream_redactor.detectors.base import StreamingRequirements, is_placeholder
from safestream_redactor.entities import Detection, EntityType

if TYPE_CHECKING:
    from types import ModuleType

# The longest span any tier-1 pattern can emit: the private-key body is bounded
# to keep the whole match within the default overlap (see the PRIVATE_KEY
# pattern's comment). Every other pattern is far shorter, so this is L_max for
# the deterministic tier.
DETERMINISTIC_MAX_SPAN = 8 * 1024

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


# Country calling codes assigned in the E.164 numbering plan (ITU-T), taken from
# libphonenumber's metadata (``phonenumbers`` 9.0.40,
# ``COUNTRY_CODE_TO_REGION_CODE``). The set is a prefix code (no code is a prefix
# of another), so the leading digits of an international number name at most one
# country. The native core carries the same table (``native/src/digits.rs``); a
# test keeps the two equal.
E164_COUNTRY_CODES: frozenset[int] = frozenset(
    (
        1,
        7,
        20,
        27,
        30,
        31,
        32,
        33,
        34,
        36,
        39,
        40,
        41,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        60,
        61,
        62,
        63,
        64,
        65,
        66,
        81,
        82,
        84,
        86,
        90,
        91,
        92,
        93,
        94,
        95,
        98,
        211,
        212,
        213,
        216,
        218,
        220,
        221,
        222,
        223,
        224,
        225,
        226,
        227,
        228,
        229,
        230,
        231,
        232,
        233,
        234,
        235,
        236,
        237,
        238,
        239,
        240,
        241,
        242,
        243,
        244,
        245,
        246,
        247,
        248,
        249,
        250,
        251,
        252,
        253,
        254,
        255,
        256,
        257,
        258,
        260,
        261,
        262,
        263,
        264,
        265,
        266,
        267,
        268,
        269,
        290,
        291,
        297,
        298,
        299,
        350,
        351,
        352,
        353,
        354,
        355,
        356,
        357,
        358,
        359,
        370,
        371,
        372,
        373,
        374,
        375,
        376,
        377,
        378,
        380,
        381,
        382,
        383,
        385,
        386,
        387,
        389,
        420,
        421,
        423,
        500,
        501,
        502,
        503,
        504,
        505,
        506,
        507,
        508,
        509,
        590,
        591,
        592,
        593,
        594,
        595,
        596,
        597,
        598,
        599,
        670,
        672,
        673,
        674,
        675,
        676,
        677,
        678,
        679,
        680,
        681,
        682,
        683,
        685,
        686,
        687,
        688,
        689,
        690,
        691,
        692,
        800,
        808,
        850,
        852,
        853,
        855,
        856,
        870,
        878,
        880,
        881,
        882,
        883,
        886,
        888,
        960,
        961,
        962,
        963,
        964,
        965,
        966,
        967,
        968,
        970,
        971,
        972,
        973,
        974,
        975,
        976,
        977,
        979,
        992,
        993,
        994,
        995,
        996,
        998,
    )
)


def e164_country_code_ok(number: str) -> bool:
    """``number`` (starting with ``+``) begins with an assigned country code.

    The digits right after the ``+`` are the writer's country-code group when a
    separator or ``(`` ends them within three digits (``+44 20 …``, ``+1-415``,
    ``+44(0)20``): that group must be an assigned code exactly, so ``+99 555 …``
    is rejected even though ``995`` (Georgia) begins its digits. An unbroken run
    (``+14155552671``) is read as E.164 itself defines it: by the unique assigned
    prefix of its leading digits. Digit values are compared, so ``+٤٤`` is ``+44``.
    """
    run = ""
    for c in number[1:]:
        if not c.isdecimal():
            break
        run += c
    if not run or int(run[0]) == 0:
        return False  # no country code starts with 0 (and "020" is not 20)
    if len(run) <= 3:
        return int(run) in E164_COUNTRY_CODES
    return any(int(run[:n]) in E164_COUNTRY_CODES for n in (1, 2, 3))


def phone_ok(match_text: str) -> bool:
    stripped = match_text.strip()
    if _DATE_SHAPE.match(stripped) or _SSN_SHAPE.match(stripped):
        return False
    digits = re.sub(r"\D", "", match_text)
    if not 7 <= len(digits) <= 15:
        return False
    # an international number must start with an assigned country code
    # (``+28 …``, ``+99 …`` are unassigned, never a real number)
    return not stripped.startswith("+") or e164_country_code_ok(stripped)


def ipv4_ok(match_text: str) -> bool:
    """Octets 0-255 with no leading zeros.

    The shape regex only checks 1-3 digits per octet; this reproduces exactly
    what the old inline alternation ``25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d``
    accepted — in particular ``01`` and ``007`` are rejected, keeping
    version-string-like quads with leading zeros out. Splitting shape from
    validation makes the scan ~2x faster (measured); a differential test pins
    the semantics to the old pattern.
    """
    return all(o == "0" or (o[0] != "0" and int(o) <= 255) for o in match_text.split("."))


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
    # Optional replacement for ``regex.finditer`` that must yield exactly the same
    # matches, used where the backtracking engine is super-linear on adversarial
    # input. An optimisation only: a differential test pins it to ``finditer``.
    scanner: Callable[[re.Pattern[str], str], Iterator[re.Match[str]]] | None = None


_DIGIT = re.compile(r"\d")

# Street suffixes in Title and UPPER case (no IGNORECASE: Python and Rust fold
# a few non-ASCII letters differently), and US states as codes and full names.
_STREET_SUFFIX = (
    "Street|STREET|St|ST|Avenue|AVENUE|Ave|AVE|Road|ROAD|Rd|RD|Boulevard|BOULEVARD|Blvd|BLVD"
    "|Lane|LANE|Ln|LN|Drive|DRIVE|Dr|DR|Way|WAY|Court|COURT|Ct|CT|Place|PLACE|Pl|PL"
    "|Parkway|PARKWAY|Pkwy|PKWY|Terrace|TERRACE|Circle|CIRCLE|Highway|HIGHWAY|Hwy|HWY"
    "|Square|SQUARE"
)
_US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE"
    "|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|PR|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY"
    "|Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida"
    "|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland"
    "|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada"
    "|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio"
    "|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee"
    "|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming"
)
# house number, one to four words, a suffix: "1100 South Marietta Pkwy", "790 8TH AVE"
_STREET_SRC = (
    rf"\b[0-9]{{1,6}}[ \t]+(?:[A-Z0-9][A-Za-z0-9'-]*\.?[ \t]+){{1,4}}(?:{_STREET_SUFFIX})\b"
)
# "Chicago,  Illinois  60690", "Leto, TX, 22231", "Albuquerque, NM 87131-0025"
_CITY_ZIP_SRC = (
    rf"\b[A-Z][A-Za-z]+(?:[ \t][A-Z][A-Za-z]+){{0,2}},[ \t]+(?:{_US_STATES}),?[ \t]+"
    rf"[0-9]{{5}}(?:-[0-9]{{4}})?\b"
)


def _email_local(c: str) -> bool:
    """The EMAIL local-part class ``[\\w.%+-]``: CPython's ``\\w`` is ``isalnum()`` or ``_``."""
    return c.isalnum() or c in "_.%+-"


_WORD_BOUNDARY = re.compile(r"\b")


def _email_scan(regex: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """``regex.finditer(text)`` for the EMAIL pattern, in linear time.

    ``finditer`` tries the pattern at every word boundary, and from each one the
    local part ``[\\w.%+-]+`` scans to the end of its run before failing
    on a missing ``@`` — O(n^2) on a long run such as ``"a.a.a.…"`` (a 32K-char
    window took ~1.3 s; an 8 MiB API body would take hours). A match needs its
    local part to be a run of local-part characters ending *exactly* at an
    ``@`` (the class excludes ``@``), so this visits only the ``@`` positions:

    * the candidate starts are the local-part run immediately left of the
      ``@``, clipped at the previous match's end (``finditer`` never starts a
      match inside an earlier one);
    * everything after the ``@`` is independent of where the local part
      started, so the pattern either matches from the *first* word boundary in
      that run or from none of them — one ``regex.match`` per ``@`` decides it.

    Each character is walked a bounded number of times, and the yielded matches
    are the same ``re.Match`` objects ``finditer`` would produce.
    """
    last_end = 0
    at = text.find("@")
    while at != -1:
        start = at
        while start > last_end and _email_local(text[start - 1]):
            start -= 1
        if start < at:
            boundary = _WORD_BOUNDARY.search(text, start, at)
            if boundary is not None and boundary.start() < at:
                m = regex.match(text, boundary.start())
                if m is not None:
                    yield m
                    last_end = m.end()
        at = text.find("@", max(at + 1, last_end))


_PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        EntityType.EMAIL,
        re.compile(r"\b[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
        anchors=("@",),
        scanner=_email_scan,
    ),
    Pattern(
        EntityType.PRIVATE_KEY,
        re.compile(
            # Key-type field bounded to {0,20}: real labels ("RSA ", "EC ",
            # "OPENSSH ", "ENCRYPTED ", ...) are far shorter, and an unbounded
            # ``*`` would otherwise let a crafted "BEGIN <megabytes> PRIVATE KEY"
            # produce a span longer than the streaming overlap.
            r"-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY-----"
            # Bounded body: a real PEM private key body is well under 8 KB even
            # for RSA-4096 (~3.2 KB of base64); 8100 covers RSA keys up to
            # ~RSA-12288. The bound also caps the scan a lazy ``+?`` would do
            # position-by-position looking for the END marker, so a crafted
            # BEGIN-without-END followed by megabytes of base64 can't cause a
            # pathological long scan. With the two {0,20} type fields and the
            # fixed markers this keeps the whole span at most 8192 characters
            # (the default overlap), so assumption A1 (docs/FORMAL_MODEL.md)
            # holds for private keys at the default configuration.
            r"[A-Za-z0-9+/=\s]{1,8100}?"
            r"-----END [A-Z0-9 ]{0,20}PRIVATE KEY-----"
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
    # AWS Secret Access Key: a 40-char base64-ish secret behind an explicit
    # "aws ... secret ... key [:=]" cue. Only the value (group 1) is redacted,
    # like URL_CREDENTIALS above. The label gate makes this precise enough to
    # score well above the entropy tier, which otherwise catches this secret only
    # weakly (conf 0.60) and not at all when nearby "test"/"example" markers
    # suppress it.
    Pattern(
        EntityType.AWS_SECRET,
        re.compile(
            r"(?i)aws[_\s-]*secret[_\s-]*(?:access[_\s-]*)?key\s*[:=]\s*"
            r"[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        0.9,
        group=1,
        anchors_lower=("aws",),
    ),
    # The value class includes common password specials (@ ! # $ % ^ & *) so a
    # value like ``P@ssw0rd-123!`` is captured whole instead of truncating at the
    # first special char. Safe to be permissive: the match is already gated by an
    # explicit key/secret/token/password label followed by ``:`` or ``=``.
    Pattern(
        EntityType.API_KEY,
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token"
            r"|token|password|passwd|pwd)\b\s*[:=]\s*[\"']?([A-Za-z0-9_@!#$%^&*./+\-]{12,128}={0,2})[\"']?"
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
    # cheap shape scan; ipv4_ok enforces the 0-255/no-leading-zero rules the
    # old inline alternation encoded (same matches, measurably faster scan)
    Pattern(
        EntityType.IPV4,
        re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)(?!\.\d)"),
        0.9,
        validator=ipv4_ok,
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
    # MAC / EUI-64: two-hex-digit groups joined by one consistent separator. At
    # least six groups, so a time (``10:14:32``) never qualifies; up to 20 so an
    # iptables ``MAC=`` field (dst+src+ethertype, 14 groups) is caught whole.
    Pattern(
        EntityType.MAC_ADDRESS,
        re.compile(
            r"(?<![\w:.-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4,18}(?![\w:-])"
        ),
        0.85,
        anchors=(":", "-"),
    ),
    # AWS account id: a bare 12-digit run is any number, so only the three places
    # AWS itself frames one count -- an ARN's account field, an AWS endpoint path
    # (SQS queue URLs), and an ECR registry host. Only the digits (group 1) are
    # redacted. Written without lookaround so a DFA engine can run them as-is.
    Pattern(
        EntityType.AWS_ACCOUNT_ID,
        re.compile(r"\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12})[:/]"),
        0.85,
        group=1,
        anchors=("arn:aws",),
    ),
    Pattern(
        EntityType.AWS_ACCOUNT_ID,
        re.compile(r"\.amazonaws\.com(?:\.cn)?/(\d{12})\b"),
        0.85,
        group=1,
        anchors=("amazonaws.com",),
    ),
    Pattern(
        EntityType.AWS_ACCOUNT_ID,
        re.compile(r"\b(\d{12})\.dkr\.ecr\."),
        0.85,
        group=1,
        anchors=(".dkr.ecr.",),
    ),
    # Postal addresses: a street line ("596 Crossover Way") and a US city/state/ZIP
    # line ("Clay, FL 17189-2021"). Gaps are [ \t] only, so a match never crosses a
    # line break into the next line or paragraph. Lookaround-free (native-ready).
    Pattern(EntityType.ADDRESS, re.compile(_STREET_SRC), 0.8, needs_digit=True),
    Pattern(EntityType.ADDRESS, re.compile(_CITY_ZIP_SRC), 0.8, needs_digit=True),
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


# --- dates / times (opt-in tier: DateDetector) -------------------------------

_MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?"
    r"|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?"
)
_DAY = r"\d{1,2}(?:st|nd|rd|th)?"
_YEAR = r"(?:19|20)\d{2}"


def numeric_date_ok(match_text: str) -> bool:
    """``a/b/y``: one of a, b is a month (1-12) and the other a day (1-31).

    A ``.``-separated run needs a four-digit year, so a version string such as
    ``1.12.20`` is not read as a date.
    """
    parts = re.split(r"([/.-])", match_text)
    a, sep, b, year = int(parts[0]), parts[1], int(parts[2]), parts[4]
    if sep == "." and len(year) != 4:
        return False
    return (1 <= a <= 12 and 1 <= b <= 31) or (1 <= a <= 31 and 1 <= b <= 12)


def textual_date_ok(match_text: str) -> bool:
    """Every number is a four-digit year or a day of the month (1-31)."""
    return all(len(n) == 4 or 1 <= int(n) <= 31 for n in re.findall(r"\d+", match_text))


_DATE_PATTERNS: tuple[Pattern, ...] = (
    # ISO 8601 date, optionally with a time and offset (2024-07-04T09:30:00Z)
    Pattern(
        EntityType.DATE,
        re.compile(
            rf"(?<![\w.-]){_YEAR}([-/.])(?:0[1-9]|1[0-2])\1(?:0[1-9]|[12]\d|3[01])"
            r"(?:[T ](?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:[.,]\d{1,9})?)?"
            r"(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?)?(?![\w-]|[.:]\d)"
        ),
        0.8,
        needs_digit=True,
    ),
    # 03/08/2026, 8-3-26, 03.08.2026 (month/day order is ambiguous; both are dates)
    Pattern(
        EntityType.DATE,
        re.compile(r"(?<![\w/.-])\d{1,2}([/.-])\d{1,2}\1(?:19|20)?\d{2}(?![\w/-]|\.\d)"),
        0.8,
        validator=numeric_date_ok,
        needs_digit=True,
    ),
    # Aug 19, 2024 / 19 August 2024 / Mon, 19 Aug 2024 / March 2025
    Pattern(
        EntityType.DATE,
        re.compile(
            r"(?<!\w)(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*\.?,?\s)?"
            rf"(?:{_MONTH}\s{_DAY}(?:,?\s{_YEAR})?"
            rf"|{_DAY}\s(?:of\s)?{_MONTH}(?:,?\s{_YEAR})?"
            rf"|{_MONTH},?\s{_YEAR})(?!\w)"
        ),
        0.8,
        validator=textual_date_ok,
        needs_digit=True,
    ),
    # time of day: 10:14, 10:14:32.123, 9:05 pm (minutes required, so 16:9 is not one)
    Pattern(
        EntityType.DATE,
        re.compile(
            r"(?<![\w:.])(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:[.,]\d{1,9})?)?"
            r"(?:\s?[AaPp]\.?[Mm]\.?(?!\w))?(?![\w:]|[.,]\d)"
        ),
        0.8,
        anchors=(":",),
    ),
)


def _load_native(backend: str) -> ModuleType | None:
    """Import the optional native core, or ``None`` to run pure Python.

    ``backend`` is one of ``"python"`` (never load native), ``"native"`` (load
    it; warn and fall back to Python if the extension is not installed), or
    ``"auto"`` (load it when present, silently fall back otherwise). Falling back
    keeps the package dependency-free: the native extra is build-from-source and
    optional, and the Python tier is the byte-identical oracle either way.
    """
    if backend == "python":
        return None
    if backend not in {"native", "auto"}:
        raise ValueError(f"backend must be 'python', 'native', or 'auto', got {backend!r}")
    try:
        import safestream_native
    except Exception:  # ImportError, or a RuntimeError from a pattern that failed to compile
        if backend == "native":
            warnings.warn(
                "backend='native' requested but the safestream_native extension is not "
                "installed; falling back to the pure-Python tier. Build it from native/ "
                "with maturin to enable the native core.",
                RuntimeWarning,
                stacklevel=3,
            )
        return None
    if not _native_matches_spec(safestream_native):  # pragma: no cover - requires native
        # The native wheel is a separate distribution; a version-skewed one could
        # pair native patterns with a different Python spec and silently diverge.
        # Fall back to the byte-identical oracle rather than ship wrong output.
        warnings.warn(
            "the installed safestream_native extension's pattern spec does not match "
            "this version of safestream-redactor (version skew); falling back to the "
            "pure-Python tier. Install matching versions (the [native] extra pins a "
            "compatible floor).",
            RuntimeWarning,
            stacklevel=3,
        )
        return None
    return cast("ModuleType", safestream_native)  # pragma: no cover - requires native extension


def _native_matches_spec(mod: Any) -> bool:
    """True if the native pattern sources match this package's Python spec.

    Source-string equality only (the same check ``tests/test_native_backend.py``
    makes at build time), lifted to runtime because a published native wheel is a
    separate distribution that can be version-skewed against the installed
    ``safestream-redactor``. It is a necessary condition for byte-identity, not a
    full proof (the Rust validators are gated by the differential test, which cannot
    run at import), but it catches the realistic skew — a changed pattern set — so
    the caller can fall back to the pure-Python oracle instead of diverging.
    """
    from safestream_redactor.detectors._lookaround_free import LF_PATTERNS
    from safestream_redactor.detectors.contextual import _BOOST_TRIGGERS, _SUPPRESS_TRIGGERS
    from safestream_redactor.detectors.labeled_id import _COMPILED as LABELED

    expected = {(p.entity_type.value, p.regex.pattern) for p in _PATTERNS}
    expected |= {(p.entity_type.value, p.candidate.pattern) for p in LF_PATTERNS}
    labeled = [(rx.pattern, etype.value, conf) for rx, etype, conf in LABELED]
    boost = {t.value: tuple(words) for t, words in _BOOST_TRIGGERS.items()}
    try:
        # the API that hands ambiguous text back to Python (older wheels lack it
        # and could diverge on such text), for every tier the core implements
        if not all(callable(getattr(mod, f, None)) for f in _NATIVE_API):
            return False
        native = [(name, src) for name, _conf, src in mod.patterns()]
        native_boost, native_suppress = mod.context_triggers()
        if not (
            [tuple(r) for r in mod.labeled_rules()] == labeled
            and {t: tuple(w) for t, w in native_boost if t} == boost
            and tuple(native_suppress) == _SUPPRESS_TRIGGERS
            and frozenset(mod.e164_country_codes()) == E164_COUNTRY_CODES
        ):
            return False
    except Exception:
        return False
    if not all(pair in expected for pair in native):
        return False
    # A covered type is routed to native wholesale, so native must implement
    # every Python pattern of that type (phone has two); otherwise the hybrid
    # would silently drop the missing one.
    python_counts = Counter(p.entity_type.value for p in _PATTERNS)
    native_counts = Counter(name for name, _src in native)
    return all(python_counts[name] == n for name, n in native_counts.items())


# the native functions this package calls; a wheel missing any is rejected
_NATIVE_API = (
    "scan_text",
    "scan_labeled_text",
    "scan_entropy_text",
    "scan_compound_text",
    "scan_bare_ssn_text",
    "adjust_text",
    "context_triggers",
    "e164_country_codes",
)


class NativeBacked:
    """A detector that may run on the optional native core.

    Holds the loaded extension module, which cannot be pickled, so it pickles as
    the backend name and reloads the module on unpickle. The parallel engine ships
    detectors to worker processes this way under the ``spawn``/``forkserver``
    start methods (macOS, Windows, Python 3.14 on Linux).
    """

    _backend: str = "python"
    _native: Any = None

    def _attach_native(self, backend: str) -> None:
        self._backend = backend
        self._native = _load_native(backend)

    @staticmethod
    def _native_call(fn: Callable[..., Any], *args: Any) -> Any:
        """``fn(*args)``, or ``None`` when the text cannot cross into Rust.

        A lone surrogate (e.g. decoded from a JSON ``"\\udcff"`` escape over the REST
        API or MCP) has no UTF-8 form, so the binding raises ``UnicodeEncodeError``
        before the core runs. ``None`` is the same signal the core uses for text it
        cannot decide, and every caller then scans the text with the Python tier.
        """
        try:
            return fn(*args)
        except UnicodeEncodeError:
            return None

    def __getstate__(self) -> dict[str, Any]:
        state = dict(self.__dict__)
        state["_native"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._native = _load_native(self._backend)


# Rules that match the value after a label rather than a self-identifying format.
_LABEL_GATED = frozenset({EntityType.API_KEY, EntityType.AWS_SECRET, EntityType.URL_CREDENTIALS})


class DeterministicDetector(NativeBacked):
    """Runs the built-in regex+validator patterns, optionally a subset of types.

    Patterns are prefiltered per call: a regex only runs when the text contains
    one of its guaranteed anchor literals (or a digit, for numeric patterns),
    which skips most of the pattern set on secret-sparse text. Prefiltering is
    an optimisation only — output is identical with it disabled
    (``prefilter=False``), and a differential test enforces that.

    ``backend`` selects the detection engine for the patterns the optional native
    (Rust) core covers. ``"python"`` (the default) runs everything in pure Python.
    ``"native"``/``"auto"`` route the native-covered patterns through the compiled
    core (SIMD literal prefilters, GIL released) and the rest through Python; the
    combined output is byte-identical to ``"python"`` (a differential test enforces
    this — the re2 precedent), and the extension is optional, so both fall back to
    pure Python when it is not installed.
    """

    name = "deterministic"
    requirements = StreamingRequirements(max_span=DETERMINISTIC_MAX_SPAN)

    def __init__(
        self,
        types: Iterable[EntityType] | None = None,
        *,
        prefilter: bool = True,
        backend: str = "python",
    ) -> None:
        wanted = set(types) if types is not None else None
        self._patterns = [p for p in _PATTERNS if wanted is None or p.entity_type in wanted]
        self._prefilter = prefilter
        self._attach_native(backend)
        # Split the (already type-filtered) pattern set into the types the native
        # core covers and the remainder Python still handles. When native is off,
        # everything runs in Python. The native branch is exercised only when the
        # optional extension is built (gated by tests/test_native_backend.py); the
        # default, no-native CI cannot reach it, hence the coverage pragma.
        if self._native is not None:  # pragma: no cover - requires native extension
            covered = frozenset(name for name, _conf, _src in self._native.patterns())
            self._native_names = frozenset(
                p.entity_type.value for p in self._patterns if p.entity_type.value in covered
            )
            self._py_patterns = [
                p for p in self._patterns if p.entity_type.value not in self._native_names
            ]
        else:
            self._native_names = frozenset()
            self._py_patterns = self._patterns

    def detect(self, text: str) -> list[Detection]:
        if self._native is None:
            found = self._detect_python(text, self._patterns)
        else:  # pragma: no cover - requires native extension
            found = self._detect_hybrid(text)
        # A label-gated credential rule matches whatever follows the label; a
        # reference or placeholder there (process.env.KEY, ${DB_PASS}, ****) is not
        # the secret. Shared Python post-filter, so both backends agree.
        return [d for d in found if not (d.entity_type in _LABEL_GATED and is_placeholder(d.text))]

    def _detect_hybrid(self, text: str) -> list[Detection]:  # pragma: no cover - native only
        """Native core for the covered types, Python for the rest.

        Reached only with the optional extension built; byte-identical to the pure
        Python path (``tests/test_native_backend.py`` enforces this). When the text
        holds a character Rust and CPython classify differently, in a place where it
        could change a match, the core returns ``None`` and the whole text goes
        through Python. The native core scans every type it implements, so
        ``_native_names`` filters its output
        to the types requested at construction. Spans come back as character offsets
        (converted in the core), so ``text[s:e]`` is exact even on non-ASCII input;
        all native-covered patterns are group-0, so the whole span is the detection.
        """
        native = self._native_call(self._native.scan_text, text)
        if native is None:
            # a character the two engines classify differently sits where it
            # could change a match, or a lone surrogate that cannot cross into
            # Rust: this text is scanned by the Python oracle
            return self._detect_python(text, self._patterns)
        names = self._native_names
        found = [
            Detection(
                start=s,
                end=e,
                text=text[s:e],
                entity_type=EntityType.from_name(ty),
                confidence=conf,
                source=self.name,
            )
            for s, e, ty, conf in native
            if ty in names
        ]
        found.extend(self._detect_python(text, self._py_patterns))
        return found

    def _detect_python(self, text: str, patterns: list[Pattern]) -> list[Detection]:
        found: list[Detection] = []
        lowered: str | None = None
        has_digit: bool | None = None
        for pattern in patterns:
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
            matches = (
                pattern.scanner(pattern.regex, text)
                if pattern.scanner is not None
                else pattern.regex.finditer(text)
            )
            for m in matches:
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


class DateDetector(DeterministicDetector):
    """Opt-in tier: calendar dates and times of day (``EntityType.DATE``).

    Off by default because logs carry a timestamp on every line; enable it with
    ``Redactor(use_dates=True)``, ``--dates``, or by naming ``date`` in ``types``.
    The patterns live outside ``_PATTERNS`` so the native parity gate and the
    default type set are untouched; this tier always runs in Python.
    """

    name = "date"

    def __init__(self) -> None:
        super().__init__(types=())
        self._patterns = self._py_patterns = list(_DATE_PATTERNS)
