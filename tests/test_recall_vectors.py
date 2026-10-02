"""Zero-miss recall vectors: every character of every sensitive value is redacted.

Each vector is ``(context, value)``: the value is embedded in a realistic line and
must be covered end to end by the detections. Coverage, not just "some detection
nearby", is the leak-relevant property: a half-redacted key is a leaked key.
None of the values contain placeholder words (example, test, sample, ...), which
the contextual tier deliberately suppresses.

The structured-PII and secret vectors run on every backend available. The
person-name vectors need the exported ONNX model (``scripts/export_onnx.py`` ->
``models/ner/``) and are skipped without it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from safestream_redactor import Redactor

_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
    "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
    "-----END RSA PRIVATE KEY-----"
)

STRUCTURED: list[tuple[str, str, str]] = [
    # (name, context with {v}, value)
    ("ssn_dashed", "employee ssn {v} on file", "512-38-4721"),
    ("ssn_labeled_bare", "Social Security Number: {v}", "512384721"),
    ("email", "reach me at {v} today", "maria.gonzalez+billing@corp-mail.io"),
    ("email_in_json", '{{"owner": "{v}", "id": 7}}', "w.zhang@hospital.org"),
    ("card_visa", "card {v} charged", "4111 1111 1111 1111"),
    ("card_mc_dashed", "payment via {v}", "5500-0000-0000-0004"),
    ("card_amex", "amex {v} on file", "340000000000009"),
    ("phone_e164", "call {v} after 5", "+1 (415) 555-0134"),
    ("phone_uk", "mobile {v}", "+44 20 7946 0958"),
    ("ipv4", "client ip {v} connected", "203.0.113.42"),
    ("ipv6", "host {v} up", "2001:db8:85a3::8a2e:370:7334"),
    ("aws_key", "rotating {v} now", "AKIA4N7Q2ZJ6H3KX9WRT"),
    (
        "aws_secret",
        "aws_secret_access_key = {v}",
        "9fT2kLq8Zr4Xw1Nb7Hc3Vd6Mj0Pe5Gs2Ya8Uo4Qi",
    ),
    ("github_pat", "GH token {v}", "ghp_R8x2Lq9Zt4Vw7Nb1Hc5Md3Kf6Pj0Ys2Ua8Ge"),
    ("slack_bot", "SLACK={v}", "xoxb-2048123412-4096123412-aB3dE5fG7hJ9kL1mN3pQ5rS7"),
    ("stripe_live", "stripe {v}", "sk_live_51Hq7Zp2Lr9Xw4Tb6NmK3vJ8c"),
    ("google_api", "maps key {v}", "AIzaSyB7q2Lr9Xw4Tb6NmK3vJ8cHd1Fg5Pk0Zs"),
    ("anthropic", "ANTHROPIC_API_KEY={v}", "sk-ant-api03-R8x2Lq9Zt4Vw7Nb1Hc5Md3Kf6Pj0Ys2Ua8GeQ"),
    ("openai_proj", "OPENAI_API_KEY={v}", "sk-proj-Qm8x2Lq9Zt4Vw7Nb1Hc5Md3Kf6Pj0Ys2Ua8Ge"),
    (
        "jwt",
        "Authorization: Bearer {v}",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQ4MjEiLCJpYXQiOjE3MTk4NDAwMDB9"
        ".Qm9ndXNTaWduYXR1cmVCeXRlc0hlcmVYWVo",
    ),
    ("pem_private_key", "key material:\n{v}\nend", _PEM),
    ("url_password", "DATABASE_URL=postgres://svc_user:{v}@db.internal:5432/app", "Zx9pQ2vL7mKw"),
    ("api_key_labeled", "api_key={v}", "Hq7Zp2Lr9Xw4Tb6N"),
    ("password_labeled", 'password: "{v}"', "c0rrect-H0rse-B4ttery!"),
    ("entropy_unlabeled", "deploying with {v} in prod", "3vQ8x7Zk2LmN9pR4sT6wY1bC5dF0gHj"),
]

NAMES: list[tuple[str, str, str]] = [
    ("honorific", "Patient was seen by Dr. {v} this morning.", "Alan Turing"),
    ("patient_cue", "Patient {v} (age 42) was admitted.", "Maria Gonzalez"),
    ("signed_by", "Signed by {v} on behalf of the board.", "Priya Ramanathan"),
    ("contact", "Contact: {v}", "Wei Zhang"),
    ("salutation", "Dear {v},", "Siobhan O'Neill"),
    ("accented", "Report filed by {v} yesterday.", "José García-Márquez"),
    ("subword_first_name", "{v} chaired the meeting.", "Olusegun Obasanjo"),
    ("mr", "Mr. {v} called back.", "Kwame Mensah"),
    ("lowercase_after_cue", "signed by {v} on behalf of the board.", "john smith"),
    ("lowercase_after_colon", "patient: {v} (age 42)", "maria gonzalez"),
]

_BACKENDS = ["python"]
if importlib.util.find_spec("safestream_native") is not None:
    _BACKENDS.append("native")

_MODEL = Path(__file__).resolve().parents[1] / "models" / "ner"


def _uncovered(redactor: Redactor, context: str, value: str) -> str:
    """The characters of ``value`` left unredacted, in order ('' = fully covered)."""
    text = context.format(v=value)
    start = text.index(value)
    covered = {i for d in redactor.detect(text) for i in range(d.start, d.end)}
    return "".join(c for i, c in enumerate(value, start) if i not in covered)


@pytest.mark.parametrize("backend", _BACKENDS)
@pytest.mark.parametrize(("name", "context", "value"), STRUCTURED, ids=[v[0] for v in STRUCTURED])
def test_structured_and_secret_vectors_fully_redacted(backend, name, context, value):
    redactor = Redactor(backend=backend)
    assert _uncovered(redactor, context, value) == "", f"{name} leaked on {backend}"


@pytest.fixture(scope="module")
def ner_redactor() -> Redactor:
    if not (_MODEL / "model.int8.onnx").exists():
        pytest.skip("no exported model; run scripts/export_onnx.py")
    pytest.importorskip("onnxruntime")
    pytest.importorskip("tokenizers")
    return Redactor(
        use_onnx=True,
        onnx_model=str(_MODEL / "model.int8.onnx"),
        onnx_vocab=str(_MODEL / "tokenizer.json"),
        onnx_labels=str(_MODEL / "labels.json"),
    )


@pytest.mark.parametrize(("name", "context", "value"), NAMES, ids=[v[0] for v in NAMES])
def test_cued_person_names_fully_redacted(ner_redactor, name, context, value):
    assert _uncovered(ner_redactor, context, value) == "", name


def test_innocent_machine_text_never_reaches_the_model():
    """Tier-1 gate: text with no name signal skips inference entirely."""
    from safestream_redactor.detectors.onnx_ner import _candidate_windows

    logs = (
        "2024-01-03T00:00:12Z INFO req 3fa2 latency 41ms status 200 path /api/v1/users\n"
        "GET /healthz 200 0.4ms upstream=10.0.0.7:8080 bytes=512 cache=HIT user login ok\n"
        "The nightly backup finished. Rollback is not required; Monitoring is green.\n"
    )
    assert _candidate_windows(logs) == []


def test_gate_sends_a_tight_window_and_recases_names_after_a_cue():
    from safestream_redactor.detectors.onnx_ner import _candidate_windows

    text = "x" * 200 + " ok\nsigned by john smith on behalf of the board, then " + "y" * 200
    ((offset, piece),) = _candidate_windows(text)
    # a window around the cue, not the whole line, with the name capitalised
    # in place so model offsets index the original text unchanged
    assert piece.startswith("signed by John Smith on behalf")
    assert len(piece) < 100
    assert text[offset : offset + len(piece)].lower() == piece.lower()
