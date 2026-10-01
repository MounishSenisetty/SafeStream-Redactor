"""Byte-identity gate for the optional native (Rust) detection core.

Runs only when the ``safestream_native`` extension is installed (built from
``native/`` with maturin); skipped otherwise, so the default CI — which does not
build the Rust extra — stays green. When present, the native core's detections
must equal the Python ``DeterministicDetector`` for the pattern types it covers,
byte-for-byte (span, type, confidence), including on Unicode-adjacent input. This
is the same absolute bar that governs every backend (the re2 precedent): diverge
and it does not ship.
"""

from __future__ import annotations

import sys
from collections import Counter

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sn = pytest.importorskip("safestream_native", reason="native core not built")

# imports after importorskip so the module skips cleanly when the native extra
# is absent (the default CI); E402 is expected for this pattern
from safestream_redactor.detectors.deterministic import DeterministicDetector  # noqa: E402
from safestream_redactor.entities import EntityType  # noqa: E402

_COVERED = {p[0] for p in sn.patterns()}
_TYPES = [EntityType.from_name(n) for n in _COVERED]


def _python(text: str) -> list[tuple]:
    dets = DeterministicDetector(types=_TYPES, prefilter=True).detect(text)
    return sorted(
        (d.start, d.end, d.text, d.entity_type.value, round(d.confidence, 6)) for d in dets
    )


def _native(text: str) -> list[tuple] | None:
    found = sn.scan_text(text)
    if found is None:  # handed back to Python: equivalent by construction
        return None
    return sorted((s, e, text[s:e], ty, round(c, 6)) for s, e, ty, c in found)


def _assert_equiv(text: str) -> None:
    native = _native(text)
    if native is None:
        assert sn.needs_python(text)
        return
    assert native == _python(text), f"native diverged: {text!r}"


def test_unicode_digit_value_matches_python_int():
    """Prove the native Unicode digit table is COMPLETE, not sampled.

    Python's int() accepts every Unicode decimal digit (category Nd), so it
    detects Unicode-digit IPv4 (e.g. ٩٩.٩.٩.٩). The native core reproduces int()
    via a 76-block (Unicode 16.0) table; this asserts native digit value == Python int() for
    EVERY Nd codepoint (and None for non-digits), so IPv4 is byte-identical for
    the installed toolchains rather than merely for a few sampled scripts.
    """
    import unicodedata

    mismatches = []
    for cp in range(0x110000):
        c = chr(cp)
        if unicodedata.category(c) == "Nd" and sn.digit_value_of(c) != int(c):
            mismatches.append(hex(cp))
    assert not mismatches, f"native digit value diverges from int() at: {mismatches[:8]}"
    # a couple of non-Nd characters must be rejected
    assert sn.digit_value_of("a") is None
    assert sn.digit_value_of("²") is None  # superscript two: Numeric, not Nd


def test_pattern_sources_match_python():
    """The native pattern sources must be byte-for-byte the validated Python spec.

    Simple credential patterns come from ``deterministic.py``; validated PII
    patterns (e.g. ssn) use the lookaround-free candidate from
    ``_lookaround_free.py`` — the DFA-ready form the native core ports.
    """
    from safestream_redactor.detectors._lookaround_free import LF_PATTERNS
    from safestream_redactor.detectors.deterministic import _PATTERNS

    expected = {(p.entity_type.value, p.regex.pattern, p.confidence) for p in _PATTERNS}
    expected |= {(p.entity_type.value, p.candidate.pattern, p.confidence) for p in LF_PATTERNS}
    for name, conf, src in sn.patterns():
        assert (name, src, conf) in expected, f"native pattern {name} drifted from the Python spec"
    # A covered type is routed to native wholesale, so native must implement every
    # Python pattern of that type (phone has two), each exactly once.
    python_counts = Counter(p.entity_type.value for p in _PATTERNS)
    native_counts = Counter(name for name, _conf, _src in sn.patterns())
    assert {n: python_counts[n] for n in native_counts} == dict(native_counts)


CORPUS = [
    "",
    # Python \\w / \\s differ from Rust's: No numerics (²), combining marks,
    # connector punctuation (‿), and \\x1c-\\x1f as whitespace
    "²bob@x.io bob@x.io² x\u0301bob@x.io \u0301bob@x.io",
    "²2001:db8::1 \u0301::1 ‿AKIAIOSFODNN7EXAMPLE ²AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----\x1cMIIEowIBAAKCAQEA\x1f-----END RSA PRIVATE KEY-----",
    "+1 (415) 555-2671²  +1 (415) 555-2671\u0301 ²555 123 4567 ‿555 123 4567",
    "mail jane.doe+x@corp.example.co and bob@x.io",
    "key AKIAIOSFODNN7EXAMPLE and ASIAABCDEFGHIJKLMNOP",
    "tok ghp_abcdefghijklmnopqrstuvwxyz0123456789 github_pat_11ABCDEFG0123456789abcdefghij",
    "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx",
    "sk_live_abcdefghijklmnop1234567890 rk_test_ABCDEFGHIJKLMNOP1234567890",
    "AIzaSy0123456789abcdefghijklmnopqrstuvw",
    "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEXY",
    "SK0123456789abcdef0123456789abcdef npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA12345678\n-----END RSA PRIVATE KEY-----",
    # SSN: boundary + validator + Unicode digits (the digit-gated PII pattern)
    "ssn 123-45-6789 ok",
    "1123-45-6789 and 123-45-67891",  # boundary-rejected both sides
    "000-12-3456 666-00-0000 900-11-2222 123-00-6789 123-45-0000",  # invalid parts
    "文字123-45-6789文字",  # unicode-adjacent -> boundary uses Unicode \\d
    "٩٩٩-٩٩-٩٩٩٩ and ١٢٣-٤٥-٦٧٨٩",  # Unicode-digit SSNs Python DOES detect
    "٠٩123-45-6789",  # preceded by a Unicode digit -> boundary rejects
    # IPv4: octet range + no-leading-zero + Unicode-digit int()
    "host 10.20.30.40 up 255.255.255.255 ok",
    "256.1.1.1 010.1.1.1 1.2.3.4.5 999.1.2.3",  # invalid / over-long
    "٩٩.٩.٩.٩ and ١٢٣.٤.5.6 and ٠٩.1.1.1",  # Unicode-digit IPv4 Python detects
    # IPv6: ipaddress parity, boundary
    "addr 2001:db8::1 ::1 :: fe80::1 g2001:db8::1 1:2:3",
    # Unicode-adjacent: native returns byte offsets internally, must emit char offsets
    "文字a@b.io文字 key AKIAIOSFODNN7EXAMPLE",
    "naïve bob@corp.io é ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "文" * 50 + " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
]


def test_equivalence_on_corpus():
    for text in CORPUS:
        _assert_equiv(text)
    _assert_equiv("\n".join(CORPUS))


_FRAGMENTS = [
    "a@b.io",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJa.bbbbbbbb.cccccccc",
    "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "123-45-6789",
    "999-88-7777",
    "000-12-3456",
    "٩٩٩-٩٩-٩٩٩٩",
    "١٢٣",
    "10.20.30.40",
    "256.1.1.1",
    "010.0.0.0",
    "٩٩.٩.٩.٩",
    "2001:db8::1",
    "::1",
    "::",
    "fe80::1",
    "文",
    "é",
    "٩",
    " ",
    "\n",
    "@",
    ".",
    "-",
    "_",
    "x",
    "9",
    "0",
    "AKIA",
    "eyJ",
    "SG.",
]

fuzzed = st.lists(st.sampled_from(_FRAGMENTS), min_size=0, max_size=30).map("".join)


@settings(max_examples=500, derandomize=True, deadline=None)
@given(text=fuzzed)
def test_equivalence_fuzzed(text):
    _assert_equiv(text)


# ---------------------------------------------------------------------------
# Wired detector: DeterministicDetector(backend="native") must be byte-identical
# to backend="python". This is the stronger, end-user-facing gate: it runs the
# FULL pattern set (all through the Rust core, or all through Python when the
# core hands ambiguous text back) and asserts the output matches pure Python
# exactly, including source and confidence. The detect-loop tests above compare
# the raw native scan in isolation.
# ---------------------------------------------------------------------------


def _det_key(dets: list) -> list[tuple]:
    return sorted(
        (d.start, d.end, d.text, d.entity_type.value, round(d.confidence, 6), d.source)
        for d in dets
    )


def _assert_backend_equiv(text: str) -> None:
    native = DeterministicDetector(backend="native")
    python = DeterministicDetector(backend="python")
    assert _det_key(native.detect(text)) == _det_key(python.detect(text)), (
        f"native backend diverged from python: {text!r}"
    )


def test_native_backend_is_active():
    """Guard the test's own premise: the native core is loaded and splitting work.

    If the extension silently fell back to Python, the equivalence tests would
    pass vacuously. Assert the hybrid split actually happened.
    """
    det = DeterministicDetector(backend="native")
    assert det._native is not None
    # every deterministic type now runs natively; Python is only the fallback
    # for text the two engines could classify differently
    from safestream_redactor.detectors.deterministic import _PATTERNS

    assert det._native_names == {p.entity_type.value for p in _PATTERNS}
    assert det._py_patterns == []


def test_native_backend_skew_falls_back(monkeypatch):
    """A version-skewed native wheel (drifted pattern spec) degrades to pure Python.

    Simulated by monkeypatching the installed extension's patterns() to a drifted
    source; the spec-guard must reject it, warn, and fall back — so a mismatched
    published wheel can never silently diverge from the Python oracle.
    """
    monkeypatch.setattr(sn, "patterns", lambda: [("email", 0.95, "WRONG-PATTERN")])
    with pytest.warns(RuntimeWarning, match="version skew"):
        det = DeterministicDetector(backend="native")
    assert det._native is None
    # and output is exactly the pure-Python result
    text = "mail bob@x.io ssn 123-45-6789 ip 10.0.0.1"
    assert _det_key(det.detect(text)) == _det_key(
        DeterministicDetector(backend="python").detect(text)
    )


def test_backend_equivalence_on_corpus():
    for text in CORPUS:
        _assert_backend_equiv(text)
    _assert_backend_equiv("\n".join(CORPUS))


# credit_card / phone and the label-gated credentials (native since 0.5)
_WIRED_FRAGMENTS = [
    *_FRAGMENTS,
    "4111 1111 1111 1111",  # Luhn-valid card
    "+1 (415) 555-2671",  # structured phone
    "555 123 4567",  # bare phone
    "aws_secret_access_key = " + "A" * 40,  # label-gated AWS secret
    "sk-ant-" + "x" * 30,  # anthropic key
    "password: hunter2hunter2",  # api_key label
    'Secret_Key="P@ssw0rd-123!xyz"',
    "mysql://root:s3cr3t-pa55@10.0.0.5/db",
    "sk-proj-" + "Z" * 25 + "-",  # trailing '-': the word-char end backtracks
    "sk-" + "Q" * 31,  # one short of the legacy 32
    "aws secret access key = " + "x/Y+" * 10,
]

wired_fuzzed = st.lists(st.sampled_from(_WIRED_FRAGMENTS), min_size=0, max_size=30).map("".join)


@settings(max_examples=500, derandomize=True, deadline=None)
@given(text=wired_fuzzed)
def test_backend_equivalence_fuzzed(text):
    _assert_backend_equiv(text)


def test_lone_surrogate_falls_back_to_python():
    """Text with a lone surrogate has no UTF-8 form and cannot reach the Rust core.

    It arrives legitimately (a JSON "\\udcff" escape over the REST API or MCP), so
    the hybrid detector must scan it with the pure-Python oracle instead of
    raising UnicodeEncodeError.
    """
    text = "bob@x.io \udcff 4111 1111 1111 1111 +1 (415) 555-2671"
    _assert_backend_equiv(text)
    assert DeterministicDetector(backend="native").detect(text)


def test_lone_surrogate_falls_back_to_python_in_every_tier():
    """The same holds for every native-backed tier of the default pipeline."""
    from safestream_redactor import Redactor

    text = (
        "ssn: 123456789 \udcff Student ID: 202184673 key zX9kQ2mVp7Lw3Rt8Yn4Bc6Df "
        "devPass_pP0p18yO3n!vT8wZ example 4111 1111 1111 1111"
    )
    native, python = Redactor(backend="native"), Redactor(backend="python")
    assert native.redact(text) == python.redact(text)
    assert native.redact(text) != text


def test_auto_backend_uses_native_silently(recwarn):
    """backend='auto' loads native when present and emits no warning."""
    det = DeterministicDetector(backend="auto")
    assert det._native is not None
    assert not recwarn.list


# ---------------------------------------------------------------------------
# Unicode class parity. Rust's regex and CPython's re define \w, \d, \s and
# case-insensitive matching differently on some code points (combining marks,
# ZWJ/ZWNJ, connector punctuation, No numerics, digits added in later Unicode
# versions, dotted/dotless i). The native core lists those code points
# (native/src/unicode_tables.rs) and hands any text where one could change a match
# back to Python. These tests prove the list is complete for this interpreter and
# that the hand-back closes the leaks it was built for.
# ---------------------------------------------------------------------------


def test_unambiguous_code_points_classify_exactly_like_cpython():
    r"""On EVERY code point the table does not flag, native \w and \d == CPython's."""
    import re

    upper, lower = re.compile("[A-Z]", re.IGNORECASE), re.compile("[a-z]", re.IGNORECASE)
    # long s (U+017F) ~ s and the Kelvin sign ~ k, in both engines
    folds_rust = {"\u017f", "\u212a"}
    mismatches = []
    for cp in range(0x110000):
        c = chr(cp)
        if 0xD800 <= cp <= 0xDFFF:
            continue  # surrogates cannot occur in a Python str passed to Rust
        word, digit, amb_word, amb_digit, amb_space, amb_fold = sn.classify(c)
        if not amb_word and word != (c.isalnum() or c == "_"):
            mismatches.append(("word", hex(cp)))
        if not amb_digit and digit != c.isdecimal():
            mismatches.append(("digit", hex(cp)))
        if not amb_space and cp >= 0x80 and c.isspace() != bool(re.fullmatch(r"\s", c)):
            mismatches.append(("space", hex(cp)))
        if cp >= 0x80 and not amb_fold:
            folds = bool(upper.fullmatch(c) or lower.fullmatch(c))
            if folds != (c in folds_rust):
                mismatches.append(("fold", hex(cp)))
    assert not mismatches, mismatches[:10]


# Each of these leaked under the previous native core: Rust treated the trailing
# combining mark / joiner / connector as a word character, so \b failed and the
# secret was not detected at all, while Python redacted it (or the reverse).
_UNICODE_EDGES = [
    "mail a@b.io\u200d end",
    "key AKIAIOSFODNN7EXAMPLE\u0301 x",
    "x 2001:db8::1\u0301 y",
    "tok npm_abcdefghijklmnopqrstuvwxyz0123456789\u203f",
    "a@b.io\u00b2",
    "\u093ea@b.io",
    "AKIAIOSFODNN7EXAMPLE\u200c",
    "fe80::1\u200d",
    "4111 1111 1111 1111\u0301",
    "\u0301+1 (415) 555-2671",
    "SİN 123-45-6789",  # dotted capital I folds to i in Python only
    "ssn 123-45-6789\x1f",
    "aws_secret_access_key = " + "A" * 40 + "\u212a",  # Kelvin sign folds to k: blocks
    "aws_secret_access_key = " + "A" * 40 + "\u017f",  # long s folds to s: blocks
    "AWS SECRET KEY: '" + "B" * 40 + "'",
    "postgres://admin:hunter2@db.internal:5432/app and https://u:p\u0301@h",
    "api_key = 'abcdefghijklmnop'\u200d token: \u0130abcdefghijklmnopq",
    "sk-ant-" + "a" * 30 + "\u0301 sk-proj-" + "b" * 30 + " sk-" + "c" * 40,
    "-----BEGIN RSA PRIVATE KEY-----\x1cMIIEowIBAAKCAQEA\x1f-----END RSA PRIVATE KEY-----",
]


@pytest.mark.parametrize("text", _UNICODE_EDGES)
def test_word_class_edges_match_python(text):
    _assert_backend_equiv(text)


def test_marks_away_from_patterns_keep_the_native_path():
    # Devanagari/Thai text is full of combining marks; they only force the
    # Python fallback when they touch something a pattern consumes
    assert not sn.needs_python("नमस्ते दुनिया ภาษาไทย")
    assert sn.scan_text("नमस्ते key AKIAIOSFODNN7EXAMPLE") is not None


# ---------------------------------------------------------------------------
# credit_card / phone: hand-written linear scanners that must pick exactly the
# match CPython's backtracking picks (greedy-longest, shorter on lookahead failure)
# ---------------------------------------------------------------------------

_DIGIT_CORPUS = [
    "card 4111 1111 1111 1111 charged",
    "4111-1111-1111-1111 and 4111111111111111 and 4111 1111 1111 1112",
    "4111 1111 1111 1111 1111 2222",  # longer than 19 digits: shorter match backtracked
    "4111 1111 1111 1111-",  # trailing '-' forbids the greedy end
    "41111111111111111111111",  # over-long run
    "-4111111111111111 x4111111111111111",
    "١١١١ ١١١١ ١١١١ ١١١١",  # Unicode digits
    "call +1 (415) 555-2671 now",
    "+44 20 7946 0958. +91-98765-43210 +1.415.555.2671",
    "(020) 7946 0958 and (415)555-2671x",
    "tel 415 555 2671 and 415.555.2671.5 and 2024-01-15 and 123-45-6789",
    "1999-12-31 2010-01-01 12 34 56 78 90 12 34",
    "a+1 415 555 2671 _(415) 555 2671 .415 555 2671",
    "+1234 (1234) 1234 1234 1234 1234",
    "+٩٩ ٩٩٩ ٩٩٩ ٩٩٩٩",
]


def test_digit_scanners_on_corpus():
    for text in _DIGIT_CORPUS:
        _assert_equiv(text)
        _assert_backend_equiv(text)


_DIGIT_PIECES = ["1", "4", "9", "0", "٣", " ", "-", ".", "(", ")", "+", "x", "_", "\n", "4111"]
_soup = st.lists(st.sampled_from(_DIGIT_PIECES), min_size=0, max_size=60).map("".join)


# Card/phone-shaped runs: digit groups of 1-5 (ASCII or Arabic-Indic) joined by
# the separators the regexes accept or reject, behind the prefixes they care
# about ('+', '(…)', a word char, '-') and in front of the lookahead breakers.
_group = st.text(alphabet="0123456789٣", min_size=1, max_size=5)
_number = st.builds(
    lambda groups, seps, prefix, suffix: (
        prefix + "".join(g + s for g, s in zip(groups, seps, strict=False)) + suffix
    ),
    st.lists(_group, min_size=1, max_size=9),
    st.lists(st.sampled_from(["", " ", "-", ".", "  ", "--", " -", "x"]), min_size=9, max_size=9),
    st.sampled_from(["", " ", "+", "+1 ", "+44-", "(", "(415) ", "(1) ", "-", "a", "_", "."]),
    st.sampled_from(["", " ", ")", "-", ".", ".5", "x", "_", " ok"]),
)


def _luhn_complete(digits: str) -> str:
    """Append the check digit that makes ``digits`` pass Luhn."""
    total = 0
    for i, c in enumerate(reversed(digits)):
        d = int(c)
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return digits + str(-total % 10)


def _grouped(digits: str, seps: list[str]) -> str:
    return "".join(c + seps[i % len(seps)] for i, c in enumerate(digits))[: -len(seps[-1]) or None]


# Luhn-valid 12-21 digit numbers, separated per digit by '', ' ' or '-'
_card = st.builds(
    lambda body, seps, prefix, suffix: prefix + _grouped(_luhn_complete(body), seps) + suffix,
    st.text(alphabet="0123456789", min_size=11, max_size=20),
    st.lists(st.sampled_from(["", "", "", " ", "-"]), min_size=1, max_size=20),
    st.sampled_from(["", " ", "-", "x", "1"]),
    st.sampled_from(["", " ", "-", "1", " 4", "-4", "x"]),
)
# 3-6 groups of 1-5 digits with single separators: the bare and structured
# phone shapes plus their near misses (a 1- or 5-digit group, a missing sep)
_phone = st.builds(
    lambda groups, seps, prefix, suffix: (
        prefix + "".join(g + sp for g, sp in zip(groups, seps, strict=False))[: -1 or None] + suffix
    ),
    st.lists(st.text(alphabet="0123456789٣", min_size=1, max_size=5), min_size=3, max_size=6),
    st.lists(st.sampled_from([" ", ".", "-", " ", "", "  "]), min_size=6, max_size=6),
    st.sampled_from(
        [
            *["", " ", "+1 ", "+44 ", "+1(415)", "(415) ", "(0)", "+", "(", "a", "."],
            # E.164: unassigned (+28, +99), leading zero (+020), 3-digit (+995)
            *["+28 ", "+99 ", "+020 ", "+995 ", "+٤٤ ", "+1", "+28", "+0"],
        ]
    ),
    st.sampled_from(["", " ", ".", ".5", "-", "x", "_", ")", " ok"]),
)
digit_fuzzed = st.one_of(
    _soup,
    _card,
    _phone,
    st.lists(st.one_of(_number, _card, _phone, _soup), min_size=1, max_size=4).map(" ".join),
)


@settings(max_examples=3000, derandomize=True, deadline=None)
@given(text=digit_fuzzed)
def test_digit_scanners_fuzzed(text):
    """Dense digit/separator soup: every greedy and lookahead corner of the three regexes."""
    _assert_equiv(text)


# ---------------------------------------------------------------------------
# labeled identifiers (detectors/labeled_id.py)
# ---------------------------------------------------------------------------


def _labeled_key(dets: list) -> list[tuple]:
    return sorted(
        (d.start, d.end, d.text, d.entity_type.value, d.confidence, d.meta["cue"]) for d in dets
    )


def _assert_labeled_equiv(text: str) -> None:
    from safestream_redactor.detectors.labeled_id import LabeledIdentifierDetector

    native = LabeledIdentifierDetector(backend="native")
    assert native._native is not None
    python = LabeledIdentifierDetector(backend="python")
    assert _labeled_key(native.detect(text)) == _labeled_key(python.detect(text)), text


_LABELED_CORPUS = [
    "Student ID: 202184673 enrolled",
    "SSN 000-12-3456 and social security number #123456789",
    "DOB: 03/08/1996, born on 1990-01-02",
    "phone: +1 (415) 555-2671; Tel 0044 20 7946 0958",
    "card number 4111 1111 1111 1111 exp",
    "IBAN GB82WEST12345698765432 account 12-3456-7890",
    "Patient MRN-0042117 badge B12345",
    "ACCOUNT   :   1234567890   and acct no. 9876543210",
    "card " + " " * 120 + "4111111111111111",  # beyond the cue window
    "ſsn 123-45-6789 and KELVIN \u212aard 4111111111111111",
]


def test_labeled_rules_match_python():
    for text in _LABELED_CORPUS:
        _assert_labeled_equiv(text)
    _assert_labeled_equiv("\n".join(_LABELED_CORPUS))


_LABEL_PIECES = [
    "ssn",
    "SSN",
    "dob",
    "phone",
    "tel",
    "card",
    "account",
    "IBAN",
    "student",
    "id",
    "no",
    "number",
    "#",
    ":",
    "=",
    "-",
    ".",
    " ",
    "  ",
    "\n",
    "/",
    "(",
    ")",
    "+",
    "4111",
    "1234567",
    "12",
    "03/08/1996",
    "GB82",
    "WEST",
    "x",
    "é",
    "\u0301",
    "İ",
]
label_fuzzed = st.lists(st.sampled_from(_LABEL_PIECES), min_size=0, max_size=25).map(" ".join)


@settings(max_examples=1500, derandomize=True, deadline=None)
@given(text=label_fuzzed)
def test_labeled_rules_fuzzed(text):
    _assert_labeled_equiv(text)


def test_labeled_rule_sources_match_python():
    from safestream_redactor.detectors.labeled_id import _COMPILED

    assert [tuple(r) for r in sn.labeled_rules()] == [
        (rx.pattern, etype.value, conf) for rx, etype, conf in _COMPILED
    ]


# ---------------------------------------------------------------------------
# Streaming: arbitrary chunk cuts through every native-covered entity type must
# give the same redaction as one whole-text pass of the pure-Python pipeline.
# ---------------------------------------------------------------------------

_STREAM_PIECES = [
    *_WIRED_FRAGMENTS,
    "Student ID: 202184673",
    "card 4111-1111-1111-1111",
    "\u0301",
    "\u200d",
    "文字",
]
stream_text = st.lists(st.sampled_from(_STREAM_PIECES), min_size=1, max_size=40).map(" ".join)


@settings(max_examples=300, derandomize=True, deadline=None)
@given(text=stream_text, cuts=st.lists(st.integers(min_value=1, max_value=97), max_size=40))
def test_native_streaming_matches_python_whole_text(text, cuts):
    from safestream_redactor import Redactor

    native = Redactor(backend="native", chunk_size=64, overlap=8192)
    python = Redactor(backend="python")
    chunks, pos = [], 0
    for n in cuts:
        if pos >= len(text):
            break
        chunks.append(text[pos : pos + n])
        pos += n
    chunks.append(text[pos:])
    assert "".join(native.redact_stream(iter(chunks))) == python.redact(text)


# ---------------------------------------------------------------------------
# Memory limits: the core grows its output buffers with try_reserve, so under an
# RLIMIT_AS cap (--memory-limit) a scan that cannot allocate raises MemoryError
# (exit 3 in the CLI) instead of aborting the interpreter. (Allocations inside
# the regex crate's lazy-DFA cache cannot fail gracefully; the memory budget
# reserves NATIVE_PER_WORKER for them so a budgeted run keeps that headroom.)
# ---------------------------------------------------------------------------

_OOM_PROBE = """
import resource, sys
import safestream_native as sn
text = "123-45-6789 " * 400_000  # ~400K matches: the output buffers dominate
sn.scan_text("warm " + text[:120_000])  # let the regex caches reach working size
with open("/proc/self/statm") as f:
    used = int(f.read().split()[0]) * resource.getpagesize()
limit = used + 30 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
try:
    sn.scan_text(text)
    print("ok")
except MemoryError:
    print("MemoryError")
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS + /proc are Linux")
def test_output_buffer_exhaustion_raises_memory_error_not_abort():
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-c", _OOM_PROBE], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr[-2000:]  # 134 would be a Rust abort
    assert proc.stdout.strip() in {"ok", "MemoryError"}


# ---------------------------------------------------------------------------
# Entropy, compound-secret and contextual tiers (native since 0.5). The whole
# default pipeline -- every tier, contextual adjust, arbitration -- must match
# backend="python" exactly, including confidences and meta.
# ---------------------------------------------------------------------------


def _pipeline_key(dets: list) -> list[tuple]:
    return sorted(
        (
            d.start,
            d.end,
            d.text,
            d.entity_type.value,
            d.confidence,  # exact float: the adjust arithmetic stays in Python
            d.source,
            tuple(sorted(d.meta.items())),
        )
        for d in dets
    )


def _assert_pipeline_equiv(text: str) -> None:
    from safestream_redactor import Redactor

    native, python = Redactor(backend="native"), Redactor(backend="python")
    assert _pipeline_key(native.detect(text)) == _pipeline_key(python.detect(text)), text
    # and every tier really ran natively (no silent fallback at construction)
    assert all(getattr(d, "_native", None) is not None for d in native._detectors[:1])


_SECRET_PIECES = [
    "zX9kQ2mVp7Lw3Rt8Yn4Bc6Df",  # base64-ish, high entropy
    "ghij0123klmn4567ghij0123klmn4567",  # H == 4.0 exactly: undecided -> Python
    "0123456789abcdef0123456789abcdef",  # hex, H == 4.0
    "deadbeefdeadbeefdeadbeefdeadbeef",  # hex, low entropy
    "abcdefghijklmnopqrstuvwxyz",  # letters only: never a secret
    "devPass_pP0p18yO3n!vT8wZ",  # compound secret
    "aaaaa!bbbbb#ccccc$ddddd",  # compound filler (distinct ratio)
    "Ab1!" * 6,
    "ssn",
    "SSN:",
    "social security",
    "123456789",
    "1234567890",
    "key",
    "token=",
    "example",
    "TEST",
    "sample",
    "KEY",  # Kelvin sign: lower-cases to 'k'
    "FA\u212aE",  # ... so this is the suppress trigger "fake"
    "fa\u212ae:",
    "0123456789abcdef0123456789abcde",  # hex, 31: below the 32-char hex minimum
    "0123456789abcdef0123456789abcdef0",  # hex, 33
    "zX9kQ2mVp7Lw3Rt8Yn4Bc6D",  # 23: below min_length 24
    "zX9kQ2mVp7Lw3Rt8Yn4Bc6Dfg",  # 25
    "İ",  # dotted capital I: hands adjust back to Python
    "card",
    "4111 1111 1111 1111",
    "call",
    "+1 (415) 555-2671",
    "a@b.io",
    " ",
    "\n",
    "-",
    "文",
]
secret_fuzzed = st.lists(st.sampled_from(_SECRET_PIECES), min_size=0, max_size=25).map(" ".join)
secret_fuzzed_tight = st.lists(st.sampled_from(_SECRET_PIECES), min_size=0, max_size=25).map(
    "".join
)


@settings(max_examples=800, derandomize=True, deadline=None)
@given(text=st.one_of(secret_fuzzed, secret_fuzzed_tight))
def test_full_pipeline_matches_python_fuzzed(text):
    _assert_pipeline_equiv(text)


def test_full_pipeline_matches_python_on_corpora():
    import random

    for text in [*CORPUS, *_DIGIT_CORPUS, *_LABELED_CORPUS, *_UNICODE_EDGES]:
        _assert_pipeline_equiv(text)
    rng = random.Random(5)
    _assert_pipeline_equiv(" ".join(rng.choice(_SECRET_PIECES) for _ in range(5000)))


def test_entropy_on_the_threshold_is_decided_in_python():
    # H == 4.0 in real arithmetic: the native core must not decide it
    [(_s, _e, entropy, decided)] = sn.scan_entropy_text(
        "ghij0123klmn4567ghij0123klmn4567", 24, 4.0, 3.0
    )
    assert not decided and abs(entropy - 4.0) < 1e-12
    [(_s, _e, entropy, decided)] = sn.scan_entropy_text("zX9kQ2mVp7Lw3Rt8Yn4Bc6Df", 24, 4.0, 3.0)
    assert decided and entropy > 4.0


def test_lowercase_to_ascii_set_is_what_the_native_core_assumes():
    # native/src/context.rs maps only these two: Kelvin -> 'k' natively,
    # 'İ' -> Python fallback. Any other non-ASCII char lowering to ASCII would
    # break trigger matching, so pin the set on the running interpreter.
    found = {
        cp
        for cp in range(0x80, 0x110000)
        if not 0xD800 <= cp <= 0xDFFF and any(ord(ch) < 0x80 for ch in chr(cp).lower())
    }
    assert found == {0x130, 0x212A}


def test_native_redactor_pickles_for_worker_processes():
    import pickle

    from safestream_redactor import Redactor

    r = pickle.loads(pickle.dumps(Redactor(backend="native")))
    assert all(d._native is not None for d in r._detectors if hasattr(d, "_native"))
    text = "key AKIAIOSFODNN7EXAMPLE token zX9kQ2mVp7Lw3Rt8Yn4Bc6Df ssn 123456789"
    assert r.redact(text) == Redactor(backend="python").redact(text)


def test_e164_table_matches_python():
    from safestream_redactor.detectors.deterministic import E164_COUNTRY_CODES

    assert frozenset(sn.e164_country_codes()) == E164_COUNTRY_CODES
