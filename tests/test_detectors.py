"""Detector unit tests: one positive and one negative case per entity type."""

from safestream_redactor import EntityType, Redactor
from safestream_redactor.detectors.deterministic import luhn_ok, ssn_ok


def types_in(text: str, **kwargs) -> set[EntityType]:
    return {d.entity_type for d in Redactor(**kwargs).detect(text)}


def test_email():
    assert EntityType.EMAIL in types_in("mail me at first.last+tag@sub.domain.co")
    assert EntityType.EMAIL not in types_in("not an email: foo@bar (no tld)")


def test_phone_international():
    assert EntityType.PHONE in types_in("call +44 20 7946 0958 today")
    assert EntityType.PHONE in types_in("phone: (03) 9876 5432")
    # too few digits
    assert EntityType.PHONE not in types_in("room 12-34")


def test_credit_card_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    assert EntityType.CREDIT_CARD in types_in("pay with 4111-1111-1111-1111 now")
    assert EntityType.CREDIT_CARD not in types_in("pay with 1234-5678-9012-3456 now")


def test_ssn_validation():
    assert ssn_ok("123-45-6789")
    assert not ssn_ok("000-45-6789")
    assert not ssn_ok("666-45-6789")
    assert not ssn_ok("923-45-6789")
    assert not ssn_ok("123-00-6789")
    assert EntityType.SSN in types_in("ssn 123-45-6789")
    assert EntityType.SSN not in types_in("ssn 000-12-3456")


def test_contextual_bare_ssn():
    # 9 bare digits only count as an SSN next to a trigger word
    assert EntityType.SSN in types_in("ssn: 123456789")
    assert EntityType.SSN not in types_in("order number 123456789")


def test_ipv4():
    assert EntityType.IPV4 in types_in("host 10.0.0.1 up")
    assert EntityType.IPV4 not in types_in("version 999.999.999.999")
    assert EntityType.IPV4 not in types_in("1.2.3.4.5 is not an ip")


def test_ipv6():
    assert EntityType.IPV6 in types_in("addr 2001:db8::1 ok")
    assert EntityType.IPV6 in types_in("addr fe80::1ff:fe23:4567:890a ok")
    assert EntityType.IPV6 not in types_in("ratio 12:34:56 ok")


def test_aws_key():
    assert EntityType.AWS_KEY in types_in("key AKIAIOSFODNN7EXAMPLE")
    assert EntityType.AWS_KEY not in types_in("key AKIA123")


def test_github_token():
    assert EntityType.GITHUB_TOKEN in types_in("tok ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert EntityType.GITHUB_TOKEN in types_in("tok github_pat_11ABCDEFG0123456789abcdefghij")
    assert EntityType.GITHUB_TOKEN not in types_in("tok ghp_short")


def test_generic_api_key():
    assert EntityType.API_KEY in types_in('api_key = "sk_live_abc123def456"')
    assert EntityType.API_KEY in types_in("password: hunter2hunter2hunter2")
    # no assignment context -> not detected as generic key
    assert EntityType.API_KEY not in types_in("the word secret alone")


def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y"
    assert EntityType.JWT in types_in(f"auth {jwt}")


def test_private_key_block():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234567890abcdef\nMIIEowIBAAKCAQEA1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert EntityType.PRIVATE_KEY in types_in(f"cert:\n{pem}\ndone")


def test_custom_words_and_patterns():
    found = Redactor(custom_words=["ProjectX"], custom_patterns=[r"\bID-\d{4}\b"]).detect(
        "projectx doc ID-1234"
    )
    assert {d.text for d in found} == {"projectx", "ID-1234"}
    assert all(d.entity_type is EntityType.CUSTOM for d in found)


def test_types_filter():
    text = "bob@x.io and 10.0.0.1"
    assert types_in(text, types=["email"]) == {EntityType.EMAIL}


def test_contextual_suppression():
    # placeholder-looking values score lower
    dets = Redactor(min_confidence=0.0).detect("fake 555-12-3456 here")
    ssn = [d for d in dets if d.entity_type is EntityType.SSN]
    assert ssn and ssn[0].confidence < 0.85


def test_overlap_resolution_card_beats_phone():
    dets = Redactor().detect("card 4111 1111 1111 1111 ok")
    assert [d.entity_type for d in dets] == [EntityType.CREDIT_CARD]
