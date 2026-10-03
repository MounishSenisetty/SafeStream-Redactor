"""Detector unit tests: one positive and one negative case per entity type."""

import builtins

import pytest

from safestream_redactor import EntityType, Redactor
from safestream_redactor.detectors.deterministic import (
    _PATTERNS,
    DeterministicDetector,
    _load_native,
    _native_matches_spec,
    luhn_ok,
    ssn_ok,
)


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


def test_phone_rejects_date_and_ssn_shapes():
    # ISO dates and SSN-shaped groups must never be flagged as phone numbers
    assert EntityType.PHONE not in types_in("event on 2024-02-04 happened")
    assert EntityType.PHONE not in types_in("value 000-21-7955 in column")


def test_bare_phone_needs_context():
    # a bare grouped number is ambiguous with ids -> only fires with a phone cue
    assert EntityType.PHONE not in types_in("row 415 555 0132 end")
    assert EntityType.PHONE in types_in("call 415 555 0132 now")


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
    assert EntityType.IPV4 in types_in("edge 255.255.255.255 and 0.0.0.0 ok")
    assert EntityType.IPV4 not in types_in("version 999.999.999.999")
    assert EntityType.IPV4 not in types_in("1.2.3.4.5 is not an ip")
    # leading-zero octets are version/ordinal shapes, not IPs (01, 007)
    assert EntityType.IPV4 not in types_in("release 1.02.3.4 shipped")
    assert EntityType.IPV4 not in types_in("build 10.0.007.1 done")
    assert EntityType.IPV4 not in types_in("octet 10.0.0.256 too big")


def test_ipv4_shape_plus_validator_matches_old_alternation():
    # The shape regex + ipv4_ok validator must accept exactly what the previous
    # inline alternation (25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d) accepted, so the
    # speedup can never silently change detection semantics.
    import re

    old = re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
    )
    samples = [
        "10.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "256.1.2.3",
        "1.2.3.256",
        "01.2.3.4",
        "1.02.3.4",
        "1.2.3.007",
        "999.999.999.999",
        "1.2.3.4.5",
        "12345.1.2.3.4",
        "1.2.3",
        "x1.2.3.4",
        "1.2.3.4x",
        "v1.2.3.4",
        "1.2.3.40",
        "1.2.3.400",
        "10.20.30.40",
        "192.168.0.1:8080",
        "..1.2.3.4",
    ]
    blob = "  ".join(samples)
    old_spans = [(m.start(), m.end()) for m in old.finditer(blob)]
    new_spans = [
        (d.start, d.end)
        for d in Redactor(types=["ipv4"], use_entropy=False, load_plugins=False).detect(blob)
        if d.entity_type is EntityType.IPV4
    ]
    assert new_spans == old_spans


def test_ipv6():
    assert EntityType.IPV6 in types_in("addr 2001:db8::1 ok")
    assert EntityType.IPV6 in types_in("addr fe80::1ff:fe23:4567:890a ok")
    assert EntityType.IPV6 not in types_in("ratio 12:34:56 ok")


def test_mac_address():
    assert EntityType.MAC_ADDRESS in types_in("hw 00-1A-2B-3C-4D-5E up")
    # iptables MAC= field: dst + src + ethertype, caught whole
    found = Redactor().detect("MAC=95:a8:88:cf:93:a8:6f:70:8a:9b:0c:1d:08:00 SRC=1")
    assert [d.text for d in found] == ["95:a8:88:cf:93:a8:6f:70:8a:9b:0c:1d:08:00"]
    for benign in ["at 10:14:32 ok", "ratio 12:34:56:78 ok", "mixed 00:1A-2B:3C-4D:5E"]:
        assert EntityType.MAC_ADDRESS not in types_in(benign), benign


def test_aws_account_id_only_where_aws_frames_it():
    for text in [
        "arn:aws:kms:us-east-1:479900703959:key/mrk-1",
        "arn:aws:iam::123456789012:role/Admin",
        "https://sqs.us-east-1.amazonaws.com/872291069523/queue",
        "123456789012.dkr.ecr.us-east-1.amazonaws.com/app",
    ]:
        found = [d for d in Redactor().detect(text) if d.entity_type is EntityType.AWS_ACCOUNT_ID]
        assert len(found) == 1 and len(found[0].text) == 12 and found[0].text.isdigit(), text
    assert EntityType.AWS_ACCOUNT_ID not in types_in("order 123456789012 shipped")


def test_dates_are_opt_in():
    text = "Date: 03/08/2026 at 10:14, signed Aug 19, 2024 (2024-07-04T09:30:00Z)"
    assert EntityType.DATE not in types_in(text)
    found = [d.text for d in Redactor(use_dates=True).detect(text)]
    assert found == ["03/08/2026", "10:14", "Aug 19, 2024", "2024-07-04T09:30:00Z"]
    assert EntityType.DATE in types_in(text, types=["date"])
    for benign in ["version 1.12.20", "ratio 16:9", "ports 3000:3000", "13/13/2020", "May I"]:
        assert EntityType.DATE not in types_in(benign, use_dates=True), benign


def test_prose_profile_enables_dates_and_explicit_flags_win():
    text = "Signed Aug 19, 2024"
    assert EntityType.DATE not in types_in(text)
    assert EntityType.DATE not in types_in(text, profile="default")
    assert EntityType.DATE in types_in(text, profile="prose")
    assert EntityType.DATE not in types_in(text, profile="prose", use_dates=False)
    assert Redactor(profile="prose").profile == "prose"
    with pytest.raises(ValueError, match="unknown profile"):
        Redactor(profile="poetry")


def test_aws_key():
    assert EntityType.AWS_KEY in types_in("key AKIAIOSFODNN7EXAMPLE")
    assert EntityType.AWS_KEY not in types_in("key AKIA123")


def test_aws_secret_access_key_labelled():
    # the 40-char secret behind an "aws secret access key" cue is caught by a
    # precise, high-confidence label pattern (not just the weaker entropy tier),
    # and only the value is the detection span
    secret = "AB12cd34" * 5  # 40 chars, mixed alphanumeric
    r = Redactor()
    dets = r.detect(f"AWS Secret Access Key: {secret}")
    aws = [d for d in dets if d.entity_type is EntityType.AWS_SECRET]
    assert aws and aws[0].text == secret
    # underscore form with '=' assignment
    assert EntityType.AWS_SECRET in types_in(f"aws_secret_access_key={secret}")
    # the label itself stays readable; only the secret value is redacted
    out = r.redact(f"aws_secret_access_key={secret}")
    assert out == "aws_secret_access_key=[REDACTED]"


def test_github_token():
    assert EntityType.GITHUB_TOKEN in types_in("tok ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert EntityType.GITHUB_TOKEN in types_in("tok github_pat_11ABCDEFG0123456789abcdefghij")
    assert EntityType.GITHUB_TOKEN not in types_in("tok ghp_short")


def test_generic_api_key():
    assert EntityType.API_KEY in types_in('api_key = "sk_live_abc123def456"')
    assert EntityType.API_KEY in types_in("password: hunter2hunter2hunter2")
    # no assignment context -> not detected as generic key
    assert EntityType.API_KEY not in types_in("the word secret alone")


def test_generic_api_key_with_special_chars():
    # a password containing @ ! # $ % ^ & * must be captured whole, not truncated
    # at the first special character (which would drop it below the 12-char floor)
    dets = Redactor(min_confidence=0.0).detect("Password: P@ssw0rd-123!#Xy end")
    api = [d for d in dets if d.entity_type is EntityType.API_KEY]
    assert api and api[0].text == "P@ssw0rd-123!#Xy"


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


def test_private_key_begin_without_end_scans_in_linear_time():
    """A BEGIN marker followed by megabytes of base64 and no END must not match
    and must not scan pathologically (ReDoS).

    Checked as a *ratio*, not a wall-clock limit: an absolute budget measures the
    machine (it failed at 2.7 s against 2.0 s on a laptop on battery under load).
    Quadrupling the input costs ~4x for a linear scan and ~16x for a quadratic
    one; each size takes the best of three runs after a warm-up to shed noise.
    """
    import time

    def hostile(n: int) -> str:
        return "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * n

    def best_of_three(n: int) -> float:
        times = []
        for _ in range(3):
            start = time.perf_counter()
            assert EntityType.PRIVATE_KEY not in types_in(hostile(n))
            times.append(time.perf_counter() - start)
        return min(times)

    types_in(hostile(1_000))  # warm-up: pattern compilation, native core load
    small, large = best_of_three(500_000), best_of_three(2_000_000)
    assert large / small < 8, (
        f"4x the input took {large / small:.1f}x as long ({small:.3f}s -> {large:.3f}s): "
        "super-linear scan (linear is ~4x, quadratic ~16x)"
    )


def test_custom_words_and_patterns():
    found = Redactor(custom_words=["ProjectX"], custom_patterns=[r"\bID-\d{4}\b"]).detect(
        "projectx doc ID-1234"
    )
    assert {d.text for d in found} == {"projectx", "ID-1234"}
    assert all(d.entity_type is EntityType.CUSTOM for d in found)


@pytest.mark.parametrize("words", [["Jo", "John"], ["John", "Jo"], ["Jo", "John", "Jo"]])
def test_custom_words_longest_match_wins(words):
    # Regex alternation is leftmost-first: with "Jo|John" the text "John" used to
    # match only "Jo", and "hn" leaked through as "[REDACTED]hn".
    assert Redactor(custom_words=words).redact("call John or Jo") == (
        "call [REDACTED] or [REDACTED]"
    )


def test_custom_invalid_pattern_raises_clear_error():
    # Regression (F6): a malformed custom regex must raise a clear, actionable
    # ValueError naming the pattern, not a bare re.error.
    from safestream_redactor.detectors.custom import CustomDetector

    with pytest.raises(ValueError, match=r"invalid custom pattern"):
        CustomDetector(patterns=["(unclosed"])


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


# --- backend selection (pure-Python behaviour; native equivalence lives in
#     tests/test_native_backend.py, which is gated on the extension being built) --


def test_backend_default_is_python():
    """The default backend loads no native core and runs everything in Python."""
    det = DeterministicDetector()
    assert det._native is None
    assert det._py_patterns is det._patterns


def test_load_native_python_returns_none():
    assert _load_native("python") is None


def test_backend_invalid_raises():
    with pytest.raises(ValueError, match="backend must be"):
        DeterministicDetector(backend="bogus")


def test_backend_native_missing_falls_back(monkeypatch):
    """backend='native' warns and degrades to pure Python when the import fails.

    Runs regardless of whether the extension is actually installed: the import is
    forced to fail, so this exercises the dependency-free fallback path in default
    CI (where the native extra is never built).
    """
    real_import = builtins.__import__

    def _no_native(name, *args, **kwargs):
        if name == "safestream_native":
            raise ImportError("simulated missing native extension")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_native)
    with pytest.warns(RuntimeWarning, match="not installed"):
        det = DeterministicDetector(backend="native")
    assert det._native is None
    # falls back to the full Python pattern set, output unchanged
    text = "ssn 123-45-6789 ip 10.0.0.1 mail bob@x.io"
    assert {d.entity_type for d in det.detect(text)} == {
        EntityType.SSN,
        EntityType.IPV4,
        EntityType.EMAIL,
    }


def test_backend_auto_missing_falls_back_silently(monkeypatch, recwarn):
    """backend='auto' degrades to Python with no warning when native is absent."""
    real_import = builtins.__import__

    def _no_native(name, *args, **kwargs):
        if name == "safestream_native":
            raise ImportError("simulated missing native extension")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_native)
    det = DeterministicDetector(backend="auto")
    assert det._native is None
    assert not recwarn.list


def test_native_spec_guard_accepts_matching_and_rejects_skew():
    """The runtime spec-guard accepts a spec-matching native module and rejects skew.

    Guards the published-wheel version-skew case without needing the extension:
    a fake module exposing patterns() whose sources match the Python spec passes;
    one with a drifted source, an unknown type, or a broken patterns() fails.
    """

    from safestream_redactor.detectors.labeled_id import _COMPILED

    class _Good:
        # every _PATTERNS source is, by construction, in the guard's expected set
        @staticmethod
        def patterns():
            return [(p.entity_type.value, p.confidence, p.regex.pattern) for p in _PATTERNS]

        @staticmethod
        def labeled_rules():
            return [(rx.pattern, etype.value, conf) for rx, etype, conf in _COMPILED]

        @staticmethod
        def context_triggers():
            from safestream_redactor.detectors.contextual import (
                _BOOST_TRIGGERS,
                _SUPPRESS_TRIGGERS,
            )

            boost = [("", [])] + [(t.value, list(w)) for t, w in _BOOST_TRIGGERS.items()]
            return boost, list(_SUPPRESS_TRIGGERS)

        @staticmethod
        def e164_country_codes():
            from safestream_redactor.detectors.deterministic import E164_COUNTRY_CODES

            return sorted(E164_COUNTRY_CODES)

        scan_text = scan_labeled_text = staticmethod(lambda text: None)
        scan_entropy_text = scan_compound_text = staticmethod(lambda *a: [])
        scan_bare_ssn_text = adjust_text = staticmethod(lambda *a: None)

    class _OldApi:
        # a pre-0.5 wheel: matching sources, but no scan_text that can hand
        # ambiguous text back to Python, so it could diverge on such text
        patterns = _Good.patterns
        labeled_rules = _Good.labeled_rules

    class _Drifted:
        @staticmethod
        def patterns():
            return [("email", 0.95, "WRONG-PATTERN")]

    class _UnknownType:
        @staticmethod
        def patterns():
            return [("not_a_real_type", 0.5, r"\d+")]

    class _Broken:
        @staticmethod
        def patterns():
            raise RuntimeError("boom")

    assert _native_matches_spec(_Good)
    assert not _native_matches_spec(_OldApi)
    assert not _native_matches_spec(_Drifted)
    assert not _native_matches_spec(_UnknownType)
    assert not _native_matches_spec(_Broken)


# --- expanded credential patterns ---------------------------------------


def test_slack_token():
    assert EntityType.SLACK_TOKEN in types_in(
        "tok xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx"
    )
    assert EntityType.SLACK_TOKEN not in types_in("tok xoxb-123")


def test_slack_webhook():
    hook = "https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx"
    assert EntityType.SLACK_WEBHOOK in types_in(f"post to {hook}")


def test_stripe_key():
    assert EntityType.STRIPE_KEY in types_in("key sk_live_abcdefghijklmnop1234567890")
    assert EntityType.STRIPE_KEY in types_in("key rk_test_ABCDEFGHIJKLMNOP1234567890")


def test_google_api_key():
    key = "AIza" + "Sy0123456789abcdefghijklmnopqrstuvw"[:35]
    assert EntityType.GOOGLE_API_KEY in types_in(f"gkey {key} end")


def test_sendgrid_key():
    key = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEXY"
    assert EntityType.SENDGRID_KEY in types_in(f"send {key}")


def test_twilio_key():
    assert EntityType.TWILIO_KEY in types_in("sid SK0123456789abcdef0123456789abcdef end")


def test_npm_token():
    assert EntityType.NPM_TOKEN in types_in("npm_abcdefghijklmnopqrstuvwxyz0123456789")


def test_openai_key():
    # legacy 48-char form and the newer project-scoped form
    assert EntityType.OPENAI_KEY in types_in("key sk-" + "AbCd1234" * 6 + " end")
    assert EntityType.OPENAI_KEY in types_in("key sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56 end")
    assert EntityType.OPENAI_KEY not in types_in("key sk-short end")


def test_anthropic_key():
    key = "sk-ant-api03-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"
    dets = Redactor().detect(f"key {key} end")
    labels = {d.entity_type for d in dets}
    assert EntityType.ANTHROPIC_KEY in labels
    # the sk-ant- prefix must not be mislabelled as an OpenAI key
    assert EntityType.OPENAI_KEY not in labels


def test_stripe_key_not_mislabelled_as_openai():
    dets = Redactor().detect("key sk_live_abcdefghijklmnop1234567890 end")
    assert EntityType.OPENAI_KEY not in {d.entity_type for d in dets}


def test_url_credentials_redact_user_and_password_not_host():
    # the password is url_credentials; the userinfo user is a username field
    r = Redactor()
    out = r.redact("dsn postgres://svc_user:S3cretPass@db.internal:5432/app up")
    assert out == "dsn postgres://[REDACTED]:[REDACTED]@db.internal:5432/app up"
    dets = r.detect("amqp://guest:changeit-1@mq.example.com/vhost")
    cred = [d for d in dets if d.entity_type is EntityType.URL_CREDENTIALS]
    assert [d.text for d in cred] == ["changeit-1"]
    # the password span must win over the overlapping "pass@host" email match
    assert not any(d.entity_type is EntityType.EMAIL for d in dets)


def test_url_without_password_is_not_flagged():
    assert EntityType.URL_CREDENTIALS not in types_in("see https://example.com/a:b page")
    assert EntityType.URL_CREDENTIALS not in types_in("clone ssh://git@github.com/org/repo.git")
    # a port is not a password
    assert EntityType.URL_CREDENTIALS not in types_in("open http://db.internal:5432/metrics")


# --- entropy / statistical tier -----------------------------------------


def test_entropy_detects_high_entropy_secret():
    assert EntityType.SECRET in types_in("secret Zx9Kq2mVp7Lw3Rt8Yn4Bc6Df1Gh5Jk0")
    # 32-char high-entropy hex (after a hash word it would be a digest: see below)
    assert EntityType.SECRET in types_in("token a3f5e8d9c2b1046789abcdef01234567")


_HEX40 = "91957296ca119fc6aab8a682b3e5dcf9bdedd74a"
_HEX64 = "61415f82180df828e3b8d638ae5bb3913a26ff9b" + "0c1d2e3f4a5b6c7d8e9f0a1b"
_UUID = "2ba5949a-ea6e-40a0-8f4b-9d659c2a7e11"
_PNG = "iVBORw0KGgozzUwp7S2FxlITmFp2FeknRE7xQfrX0aB9cD8eF7gH6iJ5"


@pytest.mark.parametrize(
    "text",
    [
        f"request_id={_UUID} status=200",
        f"commit {_HEX40}\nMerge branch 'main'",
        f"sha256:{_HEX64}  image.tar",
        f"FROM app@sha256:{_HEX64}",
        f"checksum (md5): {_HEX64[:32]}",
        f'<img src="data:image/png;base64,{_PNG}">',
    ],
)
def test_entropy_skips_identifiers_that_are_not_secrets(text):
    assert EntityType.SECRET not in types_in(text)


@pytest.mark.parametrize(
    "text",
    [
        f"API_KEY={_UUID}",  # a key is a key whatever its shape
        f"auth token: {_HEX40}",
        f"secret = {_HEX64}",
        f"password {_PNG}",
        f"blob {_HEX40}",  # hex with no hash word stays a candidate secret
    ],
)
def test_entropy_keeps_the_same_shapes_after_a_secret_key(text):
    # redacted in full, by whichever tier labels it (api_key wins some overlaps)
    value = text.split()[-1].split("=")[-1]
    assert value not in Redactor().redact(text)


def test_identifier_check_reads_only_its_own_line():
    # a secret key on the previous line does not rescue a commit hash
    out = Redactor().redact(f"password: hunter2\ncommit {_HEX40}")
    assert out == f"password: [REDACTED]\ncommit {_HEX40}"


def test_entropy_ignores_low_entropy_and_words():
    # a UUID is structured/low-entropy, and a plain word is prose
    assert EntityType.SECRET not in types_in("id 123e4567-e89b-12d3-a456-426614174000")
    assert EntityType.SECRET not in types_in("thisisalongwordwithoutanynumbers")
    # short tokens are below the length floor
    assert EntityType.SECRET not in types_in("tok Zx9Kq2mVp7")


def test_entropy_can_be_disabled():
    text = "secret Zx9Kq2mVp7Lw3Rt8Yn4Bc6Df1Gh5Jk0"
    assert EntityType.SECRET not in types_in(text, use_entropy=False)


def test_named_credential_beats_entropy():
    # a Stripe key is also high-entropy; the specific label must win
    dets = Redactor().detect("key sk_live_abcdefghijklmnop1234567890XYZ end")
    stripe = [d for d in dets if d.entity_type is EntityType.STRIPE_KEY]
    assert stripe and not any(d.entity_type is EntityType.SECRET for d in dets)


# --- bounded-span invariant (WI-1 / Theorem 1 premise A1) -----------------
#
# Streaming equivalence requires ``overlap >= L_max``, the longest span any
# detector emits. These tests pin ``L_max <= DEFAULT_OVERLAP`` for the two
# patterns that were historically unbounded, so the default configuration
# satisfies the theorem's premise. See docs/FORMAL_MODEL.md.


def test_no_detector_emits_a_span_longer_than_default_overlap():
    from safestream_redactor.engine import DEFAULT_OVERLAP

    # a hostile blob: a 20 KB high-entropy run and an over-long PEM body, both
    # of which would once have produced a single span wider than the overlap
    blob = (
        "secret " + "Zx9Kq2mVp7Lw3Rt8Yn4Bc6" * 900 + "\n"
        "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA1234" * 900 + "\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    dets = Redactor().detect(blob)
    assert dets  # the blob is not silently ignored
    assert all(d.end - d.start <= DEFAULT_OVERLAP for d in dets)


def test_over_long_entropy_run_is_fully_covered_by_consecutive_spans():
    from safestream_redactor.detectors.entropy import MAX_SPAN, EntropyDetector

    run = "Zx9Kq2mVp7Lw3Rt8Yn4Bc6Df1Gh5Jk0" * 1000  # ~32 KB, > 2 * MAX_SPAN
    text = "token " + run + " end"
    dets = EntropyDetector().detect(text)
    assert dets
    assert all(d.end - d.start <= MAX_SPAN for d in dets)
    # the whole run is covered with no gaps: spans are contiguous end-to-start
    import itertools

    spans = sorted((d.start, d.end) for d in dets)
    assert spans[0][0] == text.index(run)
    assert spans[-1][1] == text.index(run) + len(run)
    for (_, prev_end), (next_start, _) in itertools.pairwise(spans):
        assert next_start == prev_end


def test_max_private_key_span_fits_within_default_overlap():
    from safestream_redactor.detectors.deterministic import _PATTERNS
    from safestream_redactor.engine import DEFAULT_OVERLAP

    pk = next(p for p in _PATTERNS if p.entity_type is EntityType.PRIVATE_KEY)
    widest = (
        "-----BEGIN "
        + "X" * 20
        + "PRIVATE KEY-----"
        + "A" * 8100
        + "-----END "
        + "X" * 20
        + "PRIVATE KEY-----"
    )
    m = pk.regex.search(widest)
    assert m is not None
    assert len(m.group()) <= DEFAULT_OVERLAP


def test_detectors_pickle_their_backend_not_the_module():
    # NativeBacked: the parallel engine pickles detectors for spawn/forkserver
    # workers; the backend name travels, the extension module is reloaded
    import pickle

    from safestream_redactor import Redactor

    r = Redactor(backend="python")
    clone = pickle.loads(pickle.dumps(r))
    backed = [d for d in clone._detectors if hasattr(d, "_backend")]
    assert {d.name for d in backed} >= {"deterministic", "entropy", "contextual"}
    assert all(d._backend == "python" and d._native is None for d in backed)
    text = "key AKIAIOSFODNN7EXAMPLE token zX9kQ2mVp7Lw3Rt8Yn4Bc6Df ssn 123456789"
    assert clone.redact(text) == r.redact(text)


def test_international_phone_needs_an_assigned_country_code():
    from safestream_redactor.detectors.deterministic import phone_ok

    for real in ["+1 (415) 555-2671", "+44 20 7946 0958", "+44(0)20 7946 0958", "+995 32 212 3456"]:
        assert phone_ok(real), real
    assert phone_ok("+14155552671")  # unbroken run: E.164 prefix of its digits
    assert phone_ok("+٤٤ ٢٠ ٧٩٤٦ ٠٩٥٨")  # digit values, any script
    for fake in ["+28 555 123 4567", "+99 555 123 4567", "+020 555 1234", "+0205551234"]:
        assert not phone_ok(fake), fake
    # a timezone offset is not a phone number (the one RedactionBench false
    # positive this rule removes)
    assert EntityType.PHONE not in types_in("Tue Nov 28 03:17:04 +0000 2023 root")
    assert phone_ok("(415) 555-2671")  # no '+': the country-code rule does not apply


def test_entropy_key_value_token_redacts_the_value_not_the_key():
    secret = "Zx9Kq2mVp7Lw3Rt8Yn4Bc6Df1Gh5Jk0Qw"
    assert Redactor().redact(f"session={secret} ok") == "session=[REDACTED] ok"
    # a value too short or plain on its own is not an entropy secret
    assert Redactor().redact("ref=abc trace=on") == "ref=abc trace=on"


def test_label_gated_key_keeps_base64_padding_inside_the_redaction():
    out = Redactor().redact("secret: QmFzZTY0U2VjcmV0VmFsdWU== end")
    assert out == "secret: [REDACTED] end"
