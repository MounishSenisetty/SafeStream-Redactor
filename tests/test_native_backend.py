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


def test_pattern_sources_match_python():
    """The native pattern sources must be byte-for-byte the Python originals."""
    from safestream_redactor.detectors.deterministic import _PATTERNS

    py_src = {p.entity_type.value: p.regex.pattern for p in _PATTERNS}
    for name, _conf, src in sn.patterns():
        assert src == py_src[name], f"native pattern {name} drifted from Python source"


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
    "文",
    "é",
    " ",
    "\n",
    "@",
    ".",
    "-",
    "_",
    "x",
    "AKIA",
    "eyJ",
    "SG.",
    "0",
]

fuzzed = st.lists(st.sampled_from(_FRAGMENTS), min_size=0, max_size=30).map("".join)


@settings(max_examples=500, derandomize=True, deadline=None)
@given(text=fuzzed)
def test_equivalence_fuzzed(text):
    _assert_equiv(text)
