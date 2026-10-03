"""Byte-identity gate for the lookaround-free pattern spec (Phase-2 step 2).

The lookaround-free candidate+validator forms in ``detectors/_lookaround_free.py``
must produce EXACTLY the same detections (span, text, type, confidence) as the
production :class:`DeterministicDetector` for the entity types they cover. This is
the same bar that disqualified the re2 backend: if it is not byte-identical —
including on Unicode-adjacent input — it is wrong and does not become the basis of
the native core.

Coverage note: ``credit_card`` and ``phone`` are intentionally out of scope here
(they need a dedicated scanner; see ``docs/NATIVE_CORE.md``). The test asserts the
module covers everything *else* that uses lookaround, so a future pattern that
adds lookaround can't silently escape this gate.
"""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_redactor.detectors._lookaround_free import COVERED, LookaroundFreeDetector
from safestream_redactor.detectors.deterministic import _PATTERNS, DeterministicDetector
from safestream_redactor.entities import EntityType

_LOOKAROUND = re.compile(r"\(\?<[=!]|\(\?[=!]")


def _reference(text: str, prefilter: bool) -> list[tuple]:
    """Production detections restricted to the covered types, as comparable tuples."""
    dets = DeterministicDetector(prefilter=prefilter).detect(text)
    return sorted(
        (d.start, d.end, d.text, d.entity_type, round(d.confidence, 6))
        for d in dets
        if d.entity_type in COVERED
    )


def _lookaround_free(text: str, prefilter: bool) -> list[tuple]:
    dets = LookaroundFreeDetector(prefilter=prefilter).detect(text)
    return sorted((d.start, d.end, d.text, d.entity_type, round(d.confidence, 6)) for d in dets)


def _assert_equiv(text: str) -> None:
    # equivalence must hold with and without the prefilter
    assert _lookaround_free(text, False) == _reference(text, False), (
        f"no-prefilter diverged: {text!r}"
    )
    assert _lookaround_free(text, True) == _reference(text, True), f"prefilter diverged: {text!r}"


# --- the covered set must include every lookaround pattern except cc/phone ----


def test_covers_every_lookaround_pattern_except_scanner_cases():
    lookaround_types = {p.entity_type for p in _PATTERNS if _LOOKAROUND.search(p.regex.pattern)}
    scanner_cases = {EntityType.CREDIT_CARD, EntityType.PHONE}
    assert lookaround_types - scanner_cases == set(COVERED), (
        "a lookaround pattern is neither covered nor an accepted scanner case"
    )


# --- curated corpora ---------------------------------------------------------

CORPUS = [
    "",
    "ssn 123-45-6789 ok",
    "1123-45-6789",  # preceded by digit
    "123-45-67891",  # followed by digit
    "x123-45-6789x",
    "12-34-5678 999-88-7777",
    "000-12-3456 666-00-0000 900-11-2222",  # invalid area/group/serial
    "host 10.20.30.40 up",
    "010.20.30.40 and 10.20.30.40.50 and 999.1.2.3 and 1.2.3.4",
    "addr 2001:db8::1 and fe80::1%eth0 and g2001:db8::1 and ::1",
    "aws_secret_access_key = " + "A" * 40,
    "aws_secret_access_key=" + "B" * 41,  # 41 chars -> lookahead rejects
    "key sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12 done",
    "sk-ant-" + "a" * 25 + "- trailing dash",
    "tok sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56 and sk-" + "AbCd1234" * 6,
    # Unicode-adjacent (the case that broke re2)
    "文字123-45-6789文字",
    "10.20.30.40é",
    "naïve10.20.30.40",
    "٠٩123-45-6789",  # arabic-indic digits adjacent
    "sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12文",
    # MAC: consistent vs mixed separators, too few / too many groups, adjacency
    "MAC=95:a8:88:cf:93:a8:6f:70:8a:9b:0c:1d:08:00 SRC",
    "hw 00-1A-2B-3C-4D-5E and 00:1A-2B:3C-4D:5E and aa:bb:cc:dd:ee",
    "x00:11:22:33:44:55 00:11:22:33:44:55x 00:11:22:33:44:55: .00:11:22:33:44:55",
    ":".join(["ab"] * 20) + " " + ":".join(["ab"] * 21),
    "aaa:bb:cc:dd:ee:ff 00:11:22:33:44:55-66 文00:11:22:33:44:55é",
]


def test_equivalence_on_corpus():
    for text in CORPUS:
        _assert_equiv(text)
    _assert_equiv("\n".join(CORPUS))


# --- generative fuzz with adversarial adjacency + Unicode --------------------

_FRAGMENTS = [
    "123-45-6789",
    "10.20.30.40",
    "2001:db8::1",
    "aws_secret_key: ",
    "sk-ant-",
    "sk-proj-",
    "A" * 40,
    "Ab12Cd34Ef56Gh78Ij90Kl12",
    "0",
    "9",
    "-",
    ".",
    ":",
    "_",
    "/",
    "+",
    "=",
    " ",
    "\n",
    "x",
    "a",
    "文",
    "é",
    "٩",
    "abcdef",
    "999",
    "a8",
    "0c",
    "00:11:22:33:44:55",
    "aa-bb-cc-dd-ee-ff",
]

fuzzed = st.lists(st.sampled_from(_FRAGMENTS), min_size=0, max_size=40).map("".join)


@settings(max_examples=800, derandomize=True, deadline=None)
@given(text=fuzzed)
def test_equivalence_fuzzed(text):
    _assert_equiv(text)
