"""Redaction operators beyond replace/mask: Hash, Encrypt (+ Deanonymizer), Fictionalize.

Every operator here is a **pure function of** ``(key material, entity type,
matched text)``. That is not a style choice: the streaming and parallel engines
are proven byte-identical to a whole-document pass (``docs/FORMAL_MODEL.md``)
only because rewriting a span depends on nothing but the span, so a span
rendered in any window, chunk or worker gets the same replacement. A random
nonce or a per-process counter would silently break that theorem, so:

* **Hash** is a salted digest. Unkeyed hashing of a low-cardinality value (an SSN,
  a phone number) is brute-forceable by anyone who can enumerate the domain; use
  a secret salt, or prefer ``pseudonymize`` (HMAC) when a secret key is available.
* **Encrypt** is AES-256-GCM with a *synthetic* nonce: the nonce is an HMAC of
  ``(entity type, plaintext)``, in the style of SIV constructions. Equal values
  therefore produce equal tokens (the equality leak ``pseudonymize`` already
  has), distinct values get distinct nonces, and the entity type is bound as
  authenticated data so a token cannot be relabelled. :class:`Deanonymizer`
  reverses it and **fails closed**: a token that does not authenticate is left in
  place and counted, never replaced with garbage.
* **Fictionalize** swaps a value for a deterministic, type-shaped *synthetic* one
  drawn from ranges reserved for documentation or never issued (``example.com``,
  TEST-NET addresses, ``555-01xx`` phone numbers, 9xx SSN areas), so output
  stays usable in tests and demos without containing a real-looking identifier.

Encryption needs the optional ``cryptography`` package (``pip install
'safestream-redactor[crypto]'``); everything else is standard library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from safestream_redactor.errors import MissingExtraError, OperatorError

HASH_ALGORITHMS = ("sha256", "sha512")
MIN_KEY_BYTES = 16

# A token is "<TYPE:E:payload>". Encrypt refuses a value longer than this many
# UTF-8 bytes (the built-in tiers never emit more: 8192 characters x 4 bytes), so
# the longest token has a known size and the streaming restorer can buffer exactly
# that much of an unterminated token. Without the cap a very long custom-regex span
# (reachable with a large ``overlap``) produced a token the restorer could not hold:
# it was split across chunks, never decrypted, never counted, and the run "succeeded".
MAX_PLAINTEXT_BYTES = 32_768
_GCM_OVERHEAD = 12 + 16  # nonce + tag
# The payload is written in groups joined by a separator, never as one long run. The
# entropy tiers only consider runs of 20+ characters from a fixed alphabet, and "." is
# in neither alphabet, so with groups of 16 no run in a token can reach that minimum:
# the ciphertext cannot be flagged as a secret on a rescan (`detect --fail-on-detect`
# over encrypted output), by construction rather than by an exemption. An exemption
# would need unbounded left context to recognise a long token mid-window and would
# break the streaming == whole-document proof; this stays window-local and identical
# for the Python and native backends.
_GROUP = 16
_SEP = "."
_B64 = 4 * (MAX_PLAINTEXT_BYTES + _GCM_OVERHEAD) // 3
_MAX_TOKEN = _B64 + _B64 // _GROUP + 64  # payload + separators + "<TYPE:E:" + ">"
_TOKEN = re.compile(r"<([A-Z][A-Z0-9_]{0,31}):E:([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)>")


def hash_token(algorithm: str, salt: bytes, entity_type: str, text: str, length: int) -> str:
    """``<TYPE:H:hex>``: a salted digest of ``text``, truncated to ``length`` hex digits."""
    digest = hashlib.new(algorithm, salt + b"\0" + text.encode("utf-8")).hexdigest()
    return f"<{entity_type.upper()}:H:{digest[:length]}>"


# --- encrypt ---------------------------------------------------------------


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    """Independent AES-256 and nonce-derivation keys from one secret."""
    return (
        hmac.new(key, b"safestream/enc/v1", hashlib.sha256).digest(),
        hmac.new(key, b"safestream/siv/v1", hashlib.sha256).digest(),
    )


def require_crypto() -> None:
    """Raise :class:`MissingExtraError` now if the ``crypto`` extra is absent.

    Called when an encrypting policy or a :class:`Deanonymizer` is *built*, so a
    missing library fails at configuration time, not on the first match mid-stream.
    """
    try:
        import cryptography.exceptions
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
    except ImportError as exc:
        raise MissingExtraError("encrypt mode", "crypto") from exc


def _aesgcm(enc_key: bytes) -> Any:  # optional dependency, imported lazily
    require_crypto()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(enc_key)


def encrypt_token(key: bytes, entity_type: str, text: str) -> str:
    """``<TYPE:E:payload>``: deterministic authenticated encryption of ``text``."""
    label = entity_type.upper().encode("ascii")
    enc_key, siv_key = _subkeys(key)
    plaintext = text.encode("utf-8")
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise OperatorError(
            f"encrypt handles a value of at most {MAX_PLAINTEXT_BYTES} UTF-8 bytes "
            f"(got {len(plaintext)}); a longer one could not be restored by streaming"
        )
    nonce = hmac.new(siv_key, label + b"\0" + plaintext, hashlib.sha256).digest()[:12]
    sealed = _aesgcm(enc_key).encrypt(nonce, plaintext, label)
    payload = base64.urlsafe_b64encode(nonce + sealed).rstrip(b"=").decode("ascii")
    grouped = _SEP.join(payload[i : i + _GROUP] for i in range(0, len(payload), _GROUP))
    return f"<{label.decode('ascii')}:E:{grouped}>"


class Deanonymizer:
    """Reverse :func:`encrypt_token` tokens in redacted text.

    ``restored`` and ``failed`` count tokens decrypted and tokens left in place
    (wrong key, tampering, or a relabelled entity type). Nothing here ever raises
    on bad input: a token that does not authenticate is returned unchanged.
    """

    def __init__(self, key: bytes | str) -> None:
        raw = key.encode("utf-8") if isinstance(key, str) else key
        if len(raw) < MIN_KEY_BYTES:
            raise OperatorError(f"encrypt_key must be at least {MIN_KEY_BYTES} bytes")
        require_crypto()
        self._enc_key, _ = _subkeys(raw)
        self.restored = 0
        self.failed = 0

    def _decrypt(self, label: str, payload: str) -> str | None:
        from cryptography.exceptions import InvalidTag

        aes = _aesgcm(self._enc_key)  # a missing extra propagates; it is not a bad token
        try:
            payload = payload.replace(_SEP, "")
            raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            if len(raw) < _GCM_OVERHEAD:
                return None
            return str(aes.decrypt(raw[:12], raw[12:], label.encode("ascii")).decode("utf-8"))
        except (binascii.Error, ValueError, InvalidTag):  # malformed, wrong key or tampered
            return None

    def _sub(self, match: re.Match[str]) -> str:
        plain = self._decrypt(match.group(1), match.group(2))
        if plain is None:
            self.failed += 1
            return match.group(0)
        self.restored += 1
        return plain

    def restore(self, text: str) -> str:
        """Decrypt every token in ``text``."""
        return _TOKEN.sub(self._sub, text)

    def restore_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Constant-memory :meth:`restore` over chunks; a token may span any boundary."""
        carry = ""
        for chunk in chunks:
            text = carry + chunk
            cut = text.rfind("<")
            # an unterminated '<' near the end may be the start of a token
            if cut != -1 and ">" not in text[cut:] and len(text) - cut <= _MAX_TOKEN:
                carry, text = text[cut:], text[:cut]
            else:
                carry = ""
            if text:
                yield self.restore(text)
        if carry:
            yield self.restore(carry)


# --- fictionalize ----------------------------------------------------------

_FIRST = ("Alex", "Sam", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Quinn")
_LAST = ("Example", "Sample", "Testa", "Demo", "Placeholder", "Fixture", "Mockton", "Stubbs")


def _check_digit(digits: str) -> str:
    """The Luhn check digit that makes ``digits + check`` valid."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if i % 2 == 0 else 1)
        total += d - 9 if d > 9 else d
    return str((10 - total % 10) % 10)


def _card(d: bytes) -> str:
    body = "400000" + "".join(str(b % 10) for b in d[:9])  # 4000 00xx: a test BIN range
    number = body + _check_digit(body)
    return " ".join(number[i : i + 4] for i in range(0, 16, 4))


def _ipv4(d: bytes) -> str:
    net = ("192.0.2", "198.51.100", "203.0.113")[d[0] % 3]  # RFC 5737 TEST-NET
    return f"{net}.{1 + d[1] % 254}"


_FAKE: dict[str, Callable[[bytes], str]] = {
    "email": lambda d: f"user{d[:4].hex()}@example.com",
    "phone": lambda d: f"+1-555-01{d[0] % 100:02d}",  # 555-0100..0199 are fictional
    "ssn": lambda d: (
        f"9{d[0] % 100:02d}-{1 + d[1] % 99:02d}-{1 + int.from_bytes(d[2:4], 'big') % 9999:04d}"
    ),
    "credit_card": _card,
    "ipv4": _ipv4,
    "ipv6": lambda d: f"2001:db8::{d[0]:x}{d[1]:02x}",  # RFC 3849 documentation prefix
    "person": lambda d: f"{_FIRST[d[0] % 8]} {_LAST[d[1] % 8]}",
    "org": lambda d: f"Example Organization {d[0] % 100}",
    "loc": lambda d: f"Exampleville {d[0] % 100}",
    "dob": lambda d: f"19{70 + d[0] % 30}-{1 + d[1] % 12:02d}-{1 + d[2] % 28:02d}",
    "date": lambda d: f"19{70 + d[0] % 30}-{1 + d[1] % 12:02d}-{1 + d[2] % 28:02d}",
    # 00:00:5E:00:53:xx is the IANA block reserved for documentation (RFC 7042)
    "mac_address": lambda d: f"00:00:5e:00:53:{d[0]:02x}",
}


def fictionalize(key: bytes, entity_type: str, text: str) -> str:
    """A deterministic synthetic stand-in for ``text``.

    Types without a natural fake (API keys, tokens, private keys) get an opaque
    ``<TYPE_hex>`` placeholder rather than anything that resembles a credential.
    """
    d = hmac.new(key, entity_type.encode() + b"\0" + text.encode("utf-8"), hashlib.sha256).digest()
    make = _FAKE.get(entity_type)
    return make(d) if make else f"<{entity_type.upper()}_{d.hex()[:16]}>"
