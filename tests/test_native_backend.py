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

import re
import unicodedata
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


def _native(text: str) -> list[tuple]:
    return sorted((s, e, text[s:e], ty, round(c, 6)) for s, e, ty, c in sn.detect(text))


def _assert_equiv(text: str) -> None:
    assert _native(text) == _python(text), f"native diverged: {text!r}"


def test_unicode_digit_value_matches_python_int():
    """Prove the native Unicode digit table is COMPLETE, not sampled.

    Python's int() accepts every Unicode decimal digit (category Nd), so it
    detects Unicode-digit IPv4 (e.g. ٩٩.٩.٩.٩). The native core reproduces int()
    via a 76-block (Unicode 16.0) table; this asserts native digit value == Python int() for
    EVERY Nd codepoint (and None for non-digits), so IPv4 is byte-identical for
    the installed toolchains rather than merely for a few sampled scripts.
    """
    mismatches = []
    for cp in range(0x110000):
        c = chr(cp)
        if unicodedata.category(c) == "Nd" and sn.digit_value_of(c) != int(c):
            mismatches.append(hex(cp))
    assert not mismatches, f"native digit value diverges from int() at: {mismatches[:8]}"
    # a couple of non-Nd characters must be rejected
    assert sn.digit_value_of("a") is None
    assert sn.digit_value_of("²") is None  # superscript two: Numeric, not Nd


_CLASSES = (re.compile(r"\w"), re.compile(r"\d"), re.compile(r"\s"))


def test_char_classes_match_python_re():
    """Native ``\\w``/``\\d``/``\\s`` must be Python ``re``'s, for EVERY codepoint.

    Rust's own classes differ (``²`` is Python ``\\w`` but not Rust ``\\w``;
    combining marks are the reverse; Python ``\\s`` includes ``\\x1c``), and the
    regex lane's ``\\b`` follows ``\\w``, so the native core carries tables
    generated from Python's ``re``. Codepoints this interpreter's Unicode database
    leaves unassigned (``Cn``) are skipped when it is older than the tables: those
    characters were assigned later, and the tables follow the newer standard.
    """
    skip_unassigned = unicodedata.unidata_version != sn.UNICODE_VERSION
    mismatches = []
    for cp in range(0x110000):
        c = chr(cp)
        if 0xD800 <= cp <= 0xDFFF:
            continue  # lone surrogates cannot cross into Rust (see the surrogate test)
        if skip_unassigned and unicodedata.category(c) == "Cn":
            continue
        expected = tuple(cls.fullmatch(c) is not None for cls in _CLASSES)
        if sn.char_classes_of(c) != expected:
            mismatches.append(hex(cp))
    assert not mismatches, f"native classes diverge from Python re at: {mismatches[:8]}"


def _python_sources() -> Counter:
    """(type, source) for every Python pattern, as the native core must port it.

    Simple credential patterns and the credit_card/phone scanners use the
    ``deterministic.py`` regex itself; validated PII patterns (e.g. ssn) use the
    lookaround-free candidate from ``_lookaround_free.py`` — the DFA-ready form.
    """
    from safestream_redactor.detectors._lookaround_free import LF_PATTERNS
    from safestream_redactor.detectors.deterministic import _PATTERNS

    candidate = {p.entity_type.value: p.candidate.pattern for p in LF_PATTERNS}
    return Counter(
        (p.entity_type.value, candidate.get(p.entity_type.value, p.regex.pattern))
        for p in _PATTERNS
    )


def test_pattern_sources_match_python():
    """The native pattern sources must be byte-for-byte the validated Python spec.

    Compared as a multiset per covered type: a type the native core covers is
    routed to it wholesale, so it must implement EVERY Python pattern of that type
    (phone has two), each exactly once.
    """
    python = _python_sources()
    native = Counter((name, src) for name, _conf, src in sn.patterns())
    for name in {name for name, _src in native}:
        want = {k: v for k, v in python.items() if k[0] == name}
        got = {k: v for k, v in native.items() if k[0] == name}
        assert got == want, f"native pattern(s) for {name} drifted from the Python spec"


def test_scanner_patterns_are_native():
    """credit_card and both phone patterns run in the native core (no Python lane)."""
    covered = Counter(name for name, _conf, _src in sn.patterns())
    assert covered["credit_card"] == 1
    assert covered["phone"] == 2


CORPUS = [
    "",
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
    # Python \\w / \\s differ from Rust's: No numerics (²), combining marks,
    # connector punctuation (‿), and \\x1c-\\x1f as whitespace
    "²bob@x.io bob@x.io² x\u0301bob@x.io \u0301bob@x.io",
    "²2001:db8::1 \u0301::1 ‿AKIAIOSFODNN7EXAMPLE ²AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN RSA PRIVATE KEY-----\x1cMIIEowIBAAKCAQEA\x1f-----END RSA PRIVATE KEY-----",
    # credit_card: separators, backtracking to a shorter match, boundaries, Luhn
    "card 4111 1111 1111 1111 and 4111-1111-1111-1111 and 4111111111111111",
    "4111 1111 1111 1111 1111 20 digits backtracks to 16",
    "-4111111111111111 4111111111111111- 4111111111111112 41111111111111111111111",
    "12 4111111111111111 x5500 0000 0000 0004y 6011-0000-0000-0004",
    "٤١١١ ١١١١ ١١١١ ١١١١ and 4111 1111\u00a01111 1111",
    # phone: structured (+cc, (area)) and bare, dates and SSN shapes rejected
    "call +1 (415) 555-2671 or (415) 555 2671 or +44 20 7946 0958 or +12345678",
    "bare 555 123 4567 and 555.123.4567 and 555-123-4567 but 2024-01-15 and 123-45-6789",
    "a+1 555 1234 x(415) 555-2671 +1-555-123-4567. 555 123 4567-8 555 123 4567.1",
    "10.20.30.40 ٥٥٥ ١٢٣ ٤٥٦٧ +٤٤ ٢٠ ٧٩٤٦ ٠٩٥٨ (٤١٥) ٥٥٥-٢٦٧١",
    "+1 (415) 555-2671²  +1 (415) 555-2671\u0301 ²555 123 4567 ‿555 123 4567",
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
    "4111 1111 1111 1111",
    "+1 (415) 555-2671",
    "555 123 4567",
    "+",
    "(",
    ")",
    "²",
    "\u0301",
    "‿",
    "\x1c",
]

fuzzed = st.lists(st.sampled_from(_FRAGMENTS), min_size=0, max_size=30).map("".join)


@settings(max_examples=500, derandomize=True, deadline=None)
@given(text=fuzzed)
def test_equivalence_fuzzed(text):
    _assert_equiv(text)


# Character-level fuzz for the hand-rolled scanners (credit_card, phone): digits
# dominate, so random strings are dense with candidate runs, separators and the
# lookaround characters, which is where a backtracking reimplementation would
# diverge. Unicode digits, Python-only word characters (²) and Rust-only ones
# (combining mark, ‿) exercise the boundary classes.
_SCANNER_ALPHABET = [
    *"0123456789" * 4,
    *"  --..+()_aZ",
    "٤",
    "١",
    "²",
    "\u0301",
    "‿",
    "\u00a0",
    "\x1c",
]
scanner_fuzzed = st.text(alphabet=_SCANNER_ALPHABET, max_size=60)


@settings(max_examples=3000, derandomize=True, deadline=None)
@given(text=scanner_fuzzed)
def test_scanner_equivalence_fuzzed(text):
    _assert_equiv(text)


# ---------------------------------------------------------------------------
# Wired detector: DeterministicDetector(backend="native") must be byte-identical
# to backend="python". This is the stronger, end-user-facing gate: it runs the
# FULL pattern set (native-covered types through the Rust core, the remaining 5
# label-gated credential patterns -- anthropic/openai keys, URL credentials, AWS
# secret, api_key -- through Python) and asserts the combined output matches pure
# Python exactly, including source and confidence. The detect-loop tests above
# cover only the native-covered subset in isolation.
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
    assert det._native_names  # native handles some types
    assert det._py_patterns  # Python still handles the uncovered remainder


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


# the label-gated credential patterns exercise the Python lane alongside native
_WIRED_FRAGMENTS = [
    *_FRAGMENTS,
    "4111 1111 1111 1111",  # Luhn-valid card (native scanner)
    "+1 (415) 555-2671",  # structured phone (native scanner)
    "555 123 4567",  # bare phone (native scanner)
    "aws_secret_access_key = " + "A" * 40,  # label-gated AWS secret (Python lane)
    "sk-ant-" + "x" * 30,  # anthropic key (Python lane)
    "password: hunter2hunter2",  # api_key label (Python lane)
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


def test_auto_backend_uses_native_silently(recwarn):
    """backend='auto' loads native when present and emits no warning."""
    det = DeterministicDetector(backend="auto")
    assert det._native is not None
    assert not recwarn.list
