"""Prefilter correctness: anchored skipping must never change detection output.

The prefilter is a pure optimisation, so the gate here is differential: the
detector with prefiltering enabled must produce byte-identical detections to
the same detector with it disabled, across corpora dense with entities,
near-miss negatives, and anchor-free prose.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_redactor.detectors.deterministic import _PATTERNS, DeterministicDetector

POSITIVES = [
    "mail jane.doe+x@corp.example.co now",
    "card 4111 1111 1111 1111 charged",
    "ssn: 123-45-6789 on file",
    "host 192.168.0.12 and addr 2001:db8::1 up",
    "call +44 20 7946 0958 or (03) 9876 5432",
    "key AKIAIOSFODNN7EXAMPLE leaked",
    "tok ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "github_pat_11ABCDEFG0123456789abcdefghij pushed",
    "xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx posted",
    "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx",
    "sk_live_abcdefghijklmnop1234567890 and rk_test_ABCDEFGHIJKLMNOP1234567890",
    "AIzaSy0123456789abcdefghijklmnopqrstuvw gkey",
    "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEXY sent",
    "sid SK0123456789abcdef0123456789abcdef",
    "npm_abcdefghijklmnopqrstuvwxyz0123456789 published",
    "sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78 called",
    "sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56 and sk-" + "AbCd1234" * 6,
    "dsn postgres://svc:S3cretPass@db.internal:5432/app",
    'api_key = "sk_live_abc123def456" and PASSWORD: hunter2hunter2hunter2',
    "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA12345678\n-----END RSA PRIVATE KEY-----",
]

NEGATIVES = [
    # anchor-free prose: the prefilter's fast path
    "the quick brown fox jumps over the lazy dog again and again",
    "",
    "x",
    # digits and near-misses without valid entities
    "order 1234-5678-9012-3456 shipped 2024-02-04 build 999.999.999.999",
    "ratio 12:34:56 and version 1.2.3.4.5 and room 12-34",
    # anchors present but no valid match after them
    "reply to foo@bar (no tld) re k_live_ prices at SG. HQ, task SK-12",
    "sk- alone, sk-short, xox, AKIA123, npm_x, ghp_short, eyJ..",
    "see http://example.com/a:b and ssh://git@github.com/org/repo.git",
]


def _detect(text: str, prefilter: bool):
    dets = DeterministicDetector(prefilter=prefilter).detect(text)
    return [(d.start, d.end, d.text, d.entity_type, round(d.confidence, 6)) for d in dets]


def test_prefilter_is_differentially_equivalent():
    corpora = POSITIVES + NEGATIVES + ["\n".join(POSITIVES + NEGATIVES)]
    for text in corpora:
        assert _detect(text, True) == _detect(text, False), f"divergence on {text!r}"


# Generative gate: the prefilter is a pure optimisation, so prefiltered and
# unfiltered detection must be byte-identical on *arbitrary* input, not just the
# curated corpora above. Fragments include partial anchors, digits, whitespace,
# and near-miss credential shapes so the fuzzer probes the exact conditions the
# anchor/needs_digit skip logic branches on.
_FRAGMENTS = [
    "@",
    "AKIA",
    "ghp_",
    "eyJ",
    "sk-",
    "SG.",
    "xox",
    "npm_",
    "://",
    "key",
    "secret",
    "token",
    "password",
    "-----BEGIN",
    "123-45-6789",
    "4111 1111 1111 1111",
    "1.2.3.4",
    "2001:db8::1",
    "AIza",
    "k_live_",
    "  ",
    "\n",
    "0",
    "9a8b",
    "example",
    "abcXYZ",
    ":",
    "=",
    '"',
    "-",
    ".",
]

fuzzed_text = st.lists(st.sampled_from(_FRAGMENTS), min_size=0, max_size=60).map("".join)


@settings(max_examples=400, derandomize=True, deadline=None)
@given(text=fuzzed_text)
def test_prefilter_is_differentially_equivalent_on_fuzzed_input(text):
    assert _detect(text, True) == _detect(text, False), f"divergence on {text!r}"


def test_prefilter_finds_all_expected_positives():
    # guard against a prefilter that silently drops whole entity classes
    for text in POSITIVES:
        assert _detect(text, True), f"nothing detected in {text!r}"


def test_declared_anchors_are_sound_on_matches():
    """Every regex match in the corpora must contain one of its declared anchors."""
    blob = "\n".join(POSITIVES + NEGATIVES)
    for pattern in _PATTERNS:
        for m in pattern.regex.finditer(blob):
            whole = m.group(0)
            if pattern.anchors:
                assert any(a in whole for a in pattern.anchors), (
                    f"{pattern.entity_type}: match {whole!r} lacks anchors {pattern.anchors}"
                )
            if pattern.anchors_lower:
                low = whole.lower()
                assert any(a in low for a in pattern.anchors_lower), (
                    f"{pattern.entity_type}: match {whole!r} lacks {pattern.anchors_lower}"
                )
            if pattern.needs_digit:
                assert any(c.isdigit() for c in whole)
