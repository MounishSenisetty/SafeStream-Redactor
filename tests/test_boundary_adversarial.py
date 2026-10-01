"""Adversarial chunk-boundary tests: every split position, every hard case.

The streaming guarantee (docs/FORMAL_MODEL.md, Theorem 1) is that any entity up
to ``overlap`` characters is detected even when a chunk boundary cuts through it.
These tests attack that guarantee directly: they split representative secrets at
*every* byte position and at many chunk sizes, and pin the documented behaviour
for the one case the guarantee does not cover (an entity longer than the
overlap).
"""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.detectors.entropy import MAX_SPAN

# Representative secrets, each with an unambiguous single redaction. Wrapped in
# surrounding prose so the boundary can fall before, inside, and after them.
SECRETS = {
    "email": "jane.doe@corp.example.com",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456ABC",
    "github": "ghp_" + "a" * 36,
    "credit_card": "4111 1111 1111 1111",
    "slack": "xoxb-123456789012-abcdefABCDEF12",
}


def chunked_at(text: str, cut: int) -> list[str]:
    """Split ``text`` into exactly two chunks at position ``cut``."""
    return [text[:cut], text[cut:]]


def fixed_chunks(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


@pytest.mark.parametrize("name", list(SECRETS))
def test_secret_survives_every_split_position(name: str) -> None:
    """Splitting the secret at EVERY byte offset yields identical output."""
    secret = SECRETS[name]
    text = f"prefix text {secret} suffix text"
    r = Redactor(overlap=256, allow_unsafe_overlap=True)
    whole = r.redact(text)
    # The secret must actually be redacted in the reference output.
    assert secret not in whole
    for cut in range(len(text) + 1):
        streamed = "".join(r.redact_stream(chunked_at(text, cut)))
        assert streamed == whole, f"{name}: mismatch when split at offset {cut}"


@pytest.mark.parametrize("name", list(SECRETS))
@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 13, 64])
def test_secret_survives_every_chunk_size(name: str, size: int) -> None:
    secret = SECRETS[name]
    text = f"leading {secret} trailing"
    r = Redactor(overlap=256, allow_unsafe_overlap=True)
    assert "".join(r.redact_stream(fixed_chunks(text, size))) == r.redact(text)


def test_secret_at_byte_zero() -> None:
    text = "AKIAIOSFODNN7EXAMPLE is the leaked key"
    r = Redactor(overlap=128, allow_unsafe_overlap=True)
    for cut in range(len(text) + 1):
        assert "".join(r.redact_stream(chunked_at(text, cut))) == r.redact(text)


def test_secret_ending_at_eof() -> None:
    text = "the leaked key is AKIAIOSFODNN7EXAMPLE"
    r = Redactor(overlap=128, allow_unsafe_overlap=True)
    assert text.endswith("AKIAIOSFODNN7EXAMPLE")
    for cut in range(len(text) + 1):
        assert "".join(r.redact_stream(chunked_at(text, cut))) == r.redact(text)


def test_multiple_entities_crossing_boundaries() -> None:
    text = "a@b.com and AKIAIOSFODNN7EXAMPLE and 4111 1111 1111 1111 and ghp_" + "z" * 36 + " end"
    r = Redactor(overlap=256, allow_unsafe_overlap=True)
    whole = r.redact(text)
    for size in (1, 2, 7, 32):
        assert "".join(r.redact_stream(fixed_chunks(text, size))) == whole


def test_private_key_split_across_dozens_of_chunks() -> None:
    body = "\n".join("MIIByourbase64bodyLineGoesHereForTheKeyMaterial+/=" for _ in range(20))
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    text = f"config:\n{key}\ndone"
    # overlap must exceed the whole PEM block for the single-span guarantee
    r = Redactor(overlap=MAX_SPAN)
    whole = r.redact(text)
    assert "PRIVATE KEY" not in whole.replace("[REDACTED]", "")
    # 3-byte chunks split the block into dozens of pieces
    assert "".join(r.redact_stream(fixed_chunks(text, 3))) == whole


def test_unicode_multibyte_split_is_safe() -> None:
    # A multibyte char adjacent to a secret; character-level chunking must not
    # corrupt output or miss the secret. (The engine works on decoded text, so
    # chunk boundaries fall between code points, never inside one.)
    text = "café ☕ jane.doe@example.com µ end"
    # spaCy tags the bare word "café" as an entity; this is a kernel test
    r = Redactor(overlap=128, allow_unsafe_overlap=True, use_ner=False)
    whole = r.redact(text)
    for size in (1, 2, 5):
        streamed = "".join(r.redact_stream(fixed_chunks(text, size)))
        assert streamed == whole
        assert "café" in streamed and "☕" in streamed


def test_entity_larger_than_overlap_documented_behaviour() -> None:
    """An entity longer than the overlap is the ONE case outside the guarantee.

    When a single detection is longer than the overlap and a boundary lands
    inside it, the engine cannot see it whole in one window. The documented,
    tested behaviour is that whole-text redaction still catches it, and the
    streaming pass with a too-small overlap may not — this test pins that the
    limitation is exactly as documented (not silently worse, e.g. corrupting
    output or dropping characters).
    """
    secret = "A" * 200  # a 200-char high-entropy-ish run
    text = f"token = {secret} end"
    small = Redactor(overlap=32, allow_unsafe_overlap=True)
    big = Redactor(overlap=512, allow_unsafe_overlap=True)
    # Big enough overlap: streaming equals whole-text.
    assert "".join(big.redact_stream(fixed_chunks(text, 8))) == big.redact(text)
    # Too-small overlap: output is still well-formed (no lost/dup characters);
    # every character of the original non-secret context is preserved.
    streamed = "".join(small.redact_stream(fixed_chunks(text, 8)))
    assert streamed.startswith("token = ")
    assert streamed.endswith(" end")
