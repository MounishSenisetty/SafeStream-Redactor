"""Regression tests for the leaks and false positives found in a redaction audit.

Each case is an input that used to leak a value (or redact a harmless one) under
the default settings, the ones the web playground and the CLI start with.
"""

from __future__ import annotations

import codecs

import pytest

from safestream_redactor import RedactionPolicy, Redactor
from safestream_redactor.cli import main

R = "[REDACTED]"


@pytest.fixture(scope="module")
def redactor() -> Redactor:
    return Redactor()


# --- secrets that leaked whole ----------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "username: bob password: hunter2",
        "user=bob password: hunter2",
        "host=db user=bob pass: hunter2",
        "[2024-01-01 10:00] password: hunter2",
        "2024-01-01T10:00:00Z ERROR db password: hunter2",
        "# password: hunter2",
        "; password = hunter2",
        "-- password: hunter2",
        "// password: hunter2",
        '{"msg":"user x\\npassword: hunter2"}',
        "the password is hunter2",
        "password is: hunter2",
        "passwd hunter2",
        "login failed for user bob with password hunter2",
        "\ufeffpassword: hunter2",  # a UTF-8 byte-order mark before the first line
        "a@b.com\x00\x01\x02 password: hunter2",
    ],
)
def test_password_fields_anywhere_on_a_line(redactor, text):
    out = redactor.redact(text)
    assert "hunter2" not in out, out


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        ('curl -H "Authorization: Bearer 8f3a9c2b7d1e4f6a0b5c" https://x', "8f3a9c2b7d1e4f6a0b5c"),
        ('curl -H "Authorization: Bearer eyJabc.def.ghi" https://x', "eyJabc.def.ghi"),
        ("Cookie: sessionid=abc123def456ghi789; csrftoken=xyz", "abc123def456ghi789"),
        ("Set-Cookie: session=8f3a9c2b7d1e4f6a0b5c; Path=/; HttpOnly", "8f3a9c2b7d1e4f6a0b5c"),
    ],
)
def test_http_credentials(redactor, text, secret):
    out = redactor.redact(text)
    assert secret not in out, out


def test_cookie_attributes_are_kept(redactor):
    out = redactor.redact("Set-Cookie: session=8f3a9c2b7d1e4f6a0b5c; Path=/; Max-Age=3600")
    assert out == f"Set-Cookie: session={R}; Path=/; Max-Age=3600"


@pytest.mark.parametrize(
    "text",
    ["the password is incorrect", "password reset requested", "your password was changed"],
)
def test_prose_about_passwords_is_not_a_secret(redactor, text):
    assert redactor.redact(text) == text


def test_types_secret_keeps_password_fields():
    assert Redactor(types=["secret"]).redact("password: hunter2") == f"password: {R}"


# --- names --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("name: suresh", "suresh"),
        ("name=suresh", "suresh"),
        ('"name": "suresh kumar"', "suresh kumar"),
        ("<name>suresh kumar</name>", "suresh kumar"),
        ("name: suresh kumar", "suresh kumar"),
        ("Name: Suresh kumar", "Suresh kumar"),
        ("First Name: suresh", "suresh"),
        ("lastName: kumar", "kumar"),
        ('"firstName": "suresh"', "suresh"),
        ("customer_name: suresh", "suresh"),
        ("Patient: priya", "priya"),
        ("Name: Müller", "Müller"),
        ("Name: Nguyễn Văn An", "Nguyễn Văn An"),
        ("Name: José García", "José García"),
        ("Name: Jose\u0301 Garcia", "Jose\u0301 Garcia"),  # decomposed accent
        ("Name: Łukasz Żółć", "Łukasz Żółć"),
        ("Name: Иван Петров", "Иван Петров"),
        ("Name: 李明", "李明"),
        ("Name: Anne-Marie d'Arc", "Anne-Marie d'Arc"),
        ("Name: Suresh Kumar Reddy Venkata Rao", "Suresh Kumar Reddy Venkata Rao"),
        ('"name": "Suresh Kumar Reddy Venkata Rao"', "Suresh Kumar Reddy Venkata Rao"),
        ("Father's Name: Ramesh", "Ramesh"),
        ("[2024-01-01] Name: Suresh Kumar", "Suresh Kumar"),
        ("Status: ok Name: Bob Smith Phone: 9876543210", "Bob Smith"),
    ],
)
def test_names_are_redacted_whole(redactor, text, name):
    detections = [d for d in redactor.detect(text) if d.entity_type.value == "person"]
    assert [d.text for d in detections] == [name]


def test_name_ends_before_the_next_field(redactor):
    assert redactor.redact("Name: Suresh Kumar password: hunter2") == (f"Name: {R} password: {R}")


def test_name_does_not_swallow_the_log_message(redactor):
    assert redactor.redact("INFO name: Suresh Kumar logged in") == f"INFO name: {R} logged in"


@pytest.mark.parametrize(
    "text",
    [
        "name: web",
        "  - name: nginx",
        '"name": "api-gateway"',
        # one lower-case word in JSON/XML is far more often a service than a person
        '"name": "payments"',
        "<name>billing</name>",
        "patient: stable",
        "name: Production",
        "Name: Admin",
        "Name: Default Service",
        "service name: Payment Gateway",
    ],
)
def test_names_of_things_are_kept(redactor, text):
    assert redactor.redact(text) == text


# --- phone labels and Indian identifiers --------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Mobile No.: 98765-43210",
        "Ph: 9876543210",
        "Cell #: 9876543210",
        "Pincode: 560001",
        "UPI: suresh@okaxis",
    ],
)
def test_common_labels(redactor, text):
    assert redactor.redact(text).endswith(R)


# --- evasion ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a\u200b@example.com",
        "4111\u200b1111\u200b1111\u200b1111",
        "4111\u00a01111\u00a01111\u00a01111",
        "ｕｓｅｒ＠ｅｘａｍｐｌｅ．ｃｏｍ",  # noqa: RUF001
    ],
)
def test_invisible_and_lookalike_characters(redactor, text):
    assert redactor.redact(text) == R


def test_evasion_offsets_cover_the_original_characters(redactor):
    text = "mail a\u200b@example.com now"
    (det,) = redactor.detect(text)
    assert text[det.start : det.end] == det.text == "a\u200b@example.com"


# --- false positives ----------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'integrity="sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="',
        "trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
        "path=/var/lib/kubelet/pods/7f9c1b2a-3d4e-5f60-7a8b-9c0d1e2f3a4b/volumes",
        "Release v10.4.2.1 deployed",
        "Version: 2.10.4 (build 4111111111111111)",
        "api_key: YOUR_API_KEY_HERE",
    ],
)
def test_harmless_values_are_kept(redactor, text):
    assert redactor.redact(text) == text


@pytest.mark.parametrize(
    "text", ["host 10.4.2.1", "order 4111111111111111", "token=8f3a9c2b7d1e4f6a0b5c9d8e7f6a5b4c"]
)
def test_real_values_near_those_rules_are_still_redacted(redactor, text):
    assert redactor.redact(text) != text


# --- mask mode and pseudonyms ----------------------------------------------------------


def test_mask_never_shows_part_of_a_password_or_name():
    r = Redactor(policy=RedactionPolicy(mode="mask", mask_keep_last=4))
    assert r.redact("password: hunter2 Name: Suresh Kumar a@b.com") == (
        "password: ******* Name: ************ *******"
    )


def test_pseudonyms_ignore_email_case():
    r = Redactor(policy=RedactionPolicy(mode="pseudonymize", hmac_key="k"))
    first, second = r.redact("a@b.com A@B.COM").split()
    assert first == second


# --- custom rules ---------------------------------------------------------------------


def test_custom_words_match_whole_words_only():
    assert Redactor(custom_words=["ann"]).redact("Ann annual banner ann.") == (
        f"{R} annual banner {R}."
    )


def test_custom_phrases_match_across_whitespace():
    r = Redactor(custom_words=["Project Falcon"])
    assert r.redact("Project  Falcon\nProject\nFalcon") == f"{R}\n{R}"


def test_custom_word_with_punctuation_edges():
    assert Redactor(custom_words=["#tag", "a.b*c"]).redact("x#tag a.b*c") == f"x{R} {R}"


def test_custom_regex_anchors_are_per_line():
    assert Redactor(custom_patterns=[r"^secret$"]).redact("a\nsecret\nb") == f"a\n{R}\nb"


# --- files and the CLI ----------------------------------------------------------------


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_wide_unicode_files_are_scanned(tmp_path, codec):
    bom = {"utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}.get(codec, b"")
    src = tmp_path / "in.txt"
    src.write_bytes(bom + "email a@b.com\npassword: hunter2\n".encode(codec))
    out = tmp_path / "out.txt"
    Redactor().redact_file(src, out)
    data = out.read_bytes()
    text = data.decode("utf-32" if codec == "utf-32" else "utf-16")
    assert text == f"email {R}\npassword: {R}\n"


def test_utf16_to_stdout_writes_one_bom(tmp_path, capfdbinary):
    src = tmp_path / "in.txt"
    src.write_bytes("a@b.com\n".encode("utf-16"))
    assert main(["redact", str(src), "-o", "-", "--chunk-size", "4"]) == 0
    out = capfdbinary.readouterr().out
    assert out.decode("utf-16") == f"{R}\n"
    assert out.count(codecs.BOM_UTF16_LE) + out.count(codecs.BOM_UTF16_BE) == 1


def test_hmac_key_from_environment(tmp_path, capsys, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("a@b.com\n")
    monkeypatch.setenv("SAFESTREAM_HMAC_KEY", "k")
    assert main(["redact", str(src), "-o", "-", "--mode", "pseudonymize"]) == 0
    assert capsys.readouterr().out.startswith("<EMAIL_")


def test_hash_salt_from_environment(tmp_path, capsys, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("a@b.com\n")
    main(["redact", str(src), "-o", "-", "--mode", "hash"])
    unsalted = capsys.readouterr().out
    monkeypatch.setenv("SAFESTREAM_HASH_SALT", "s")
    main(["redact", str(src), "-o", "-", "--mode", "hash"])
    assert capsys.readouterr().out != unsalted


# --- streaming equivalence still holds for the new rules ----------------------------


def test_new_rules_are_chunking_invariant():
    text = (
        "[2024-01-01] user=bob password: hunter2 Name: Suresh kumar\n"
        'curl -H "Authorization: Bearer 8f3a9c2b7d1e4f6a0b5c" https://x\n'
        "Cookie: sessionid=abc123def456ghi789\n"
        "mail a\u200b@example.com, card 4111\u00a01111\u00a01111\u00a01111\n"
    ) * 50
    r = Redactor(chunk_size=512, overlap=256, allow_unsafe_overlap=True)
    whole = r.redact(text)
    for size in (1, 7, 64, 333):
        pieces = [text[i : i + size] for i in range(0, len(text), size)]
        assert "".join(r.redact_stream(pieces)) == whole


# --- operator feedback ---------------------------------------------------------------


def test_api_warns_about_ignored_fields():
    from safestream_redactor.api import dispatch

    status, body = dispatch(Redactor(), "POST", "/redact", b'{"text": "a@b.com", "mode": "x"}')
    assert status == 200
    assert body["redacted"] == R
    assert body["warnings"] == ["unknown field 'mode' ignored: this server's own settings apply"]
    _, plain = dispatch(Redactor(), "POST", "/redact", b'{"text": "a@b.com"}')
    assert "warnings" not in plain


def test_workers_on_a_small_file_says_it_ran_as_one_process(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("a@b.com\n")
    assert main(["redact", str(src), "-o", str(tmp_path / "out.txt"), "--workers", "2"]) == 0
    assert "ran as one process" in capsys.readouterr().err
