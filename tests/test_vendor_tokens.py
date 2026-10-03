"""Vendor tokens and password hashes: detected over their WHOLE span.

Specimens are constructed in each vendor's documented format (not taken from any
evaluation corpus). A prefix or tail left in the clear is a leak, so every
positive asserts the detection covers the entire token.
"""

from __future__ import annotations

import pytest

from safestream_redactor import Redactor
from safestream_redactor.entities import EntityType

_B64ISH = "aB9cD8eF7gH6iJ5kL4mN3oP2qR1sT0uV_wX-yZ"
_HEX = "0123456789abcdef"
_UUID = "8f14e45f-ceea-467a-9575-0d43b2c4a1f9"


def _repeat(alphabet: str, n: int) -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


VENDOR = {
    "atlassian": "ATATT3" + _repeat("xFfGF0aB9_cD8-eF7=", 186),
    "doppler_service": "dp.st.prod." + _repeat("aB9cD8eF7g", 40),
    "doppler_personal": "dp.pt." + _repeat("Zz09Yy18Xx", 43),
    "dropbox": "sl." + _repeat(_B64ISH, 140),
    "vault_service": "hvs." + _repeat(_B64ISH, 90),
    "vault_batch": "hvb." + _repeat(_B64ISH, 120),
    "mapbox": "pk.eyJ1IjoibWFwdXNlciIsImEiOiJja2V5In0." + _repeat("AbCdEfGh12", 22),
    "teams": "https://contoso.webhook.office.com/webhookb2/"
    + f"{_UUID}@{_UUID}/IncomingWebhook/{_repeat(_HEX, 32)}/{_UUID}",
    "salesforce": "00D5g000004XyZa!AQ4AQ" + _repeat("aB9.cD8_eF7", 90),
    "telegram": "123456789:AA" + _repeat("aB9cD8eF7gH6_-", 33),
    "newrelic": "NRAK-" + _repeat("A1B2C3D4E5F6G7H8J9K0", 27),
    "mailgun": "key-" + _repeat(_HEX, 32),
}
HASHES = {
    "bcrypt": "$2b$12$" + _repeat("./AbCdEf0123", 53),
    "sha512crypt": "$6$saltsalt$" + _repeat("./AbCdEf0123", 86),
    "sha256crypt_rounds": "$5$rounds=5000$saltsalt$" + _repeat("./AbCdEf0123", 43),
    "md5crypt": "$1$abcdefgh$" + _repeat("./AbCdEf0123", 22),
    "apr1": "$apr1$abcdefgh$" + _repeat("./AbCdEf0123", 22),
    "cisco8": "$8$" + _repeat("AbCdEf0123", 14) + "$" + _repeat("./AbCdEf0123", 43),
    "argon2": "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMg$" + _repeat("AbCd+/0123", 43),
    "pbkdf2_django": "pbkdf2_sha256$260000$abcdefgh$" + _repeat("AbCd+/0123", 44),
    "kerberos": "$krb5asrep$23$user@CORP.LOCAL:" + _repeat(_HEX, 32) + "$" + _repeat(_HEX, 200),
}


@pytest.mark.parametrize("name", sorted(VENDOR))
def test_vendor_token_is_detected_whole(name):
    token = VENDOR[name]
    text = f"config value {token} end"
    dets = [d for d in Redactor().detect(text) if d.entity_type is EntityType.VENDOR_TOKEN]
    assert [d.text for d in dets] == [token], name
    assert Redactor().redact(text) == "config value [REDACTED] end"


@pytest.mark.parametrize("name", sorted(HASHES))
def test_password_hash_is_detected_whole(name):
    digest = HASHES[name]
    text = f"stored {digest} end"
    dets = [d for d in Redactor().detect(text) if d.entity_type is EntityType.PASSWORD_HASH]
    assert [d.text for d in dets] == [digest], name
    assert Redactor().redact(text) == "stored [REDACTED] end"


@pytest.mark.parametrize(
    "text",
    [
        "see sl.no 4 in the table",  # "sl." without a long token
        "a key-value store",  # key- without 32 hex
        "host dp.example.com",
        "fee of $1$ per item",
        "NRAK-short",
        "order 00D in stock!",
        "time 12:AA:01",
        "ratio $5$ to $6$",
        "visit https://outlook.office.com/mail/inbox",  # not a webhook path
    ],
)
def test_near_misses_are_not_tokens(text):
    types = {d.entity_type for d in Redactor().detect(text)}
    assert not types & {EntityType.VENDOR_TOKEN, EntityType.PASSWORD_HASH}, text


def test_tokens_are_redacted_whole_across_chunk_boundaries():
    # streaming: a token straddling chunk cuts is still emitted whole
    token = VENDOR["atlassian"]
    text = ("x" * 1000 + "\n") * 3 + token + "\n" + ("y" * 1000 + "\n") * 3
    r = Redactor(chunk_size=1024)
    out = "".join(r.redact_stream(text[i : i + 700] for i in range(0, len(text), 700)))
    assert token not in out and "ATATT3" not in out
