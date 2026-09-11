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
    via a 66-block table; this asserts native digit value == Python int() for
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

    expected = {p.entity_type.value: p.regex.pattern for p in _PATTERNS}
    expected.update({p.entity_type.value: p.candidate.pattern for p in LF_PATTERNS})
    for name, _conf, src in sn.patterns():
        assert src == expected[name], f"native pattern {name} drifted from the Python spec"


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
