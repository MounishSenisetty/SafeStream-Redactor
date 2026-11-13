"""User names in authentication log messages (opt-in tier)."""

from __future__ import annotations

import pytest

from safestream_redactor.detectors.log_username import LogUsernameDetector
from safestream_redactor.entities import EntityType
from safestream_redactor.redactor import Redactor

# One line per documented message format; the expected names are fake.
CASES = [
    ("Accepted password for alice from 192.0.2.7 port 51000 ssh2", ["alice"]),
    ("Accepted publickey for deploy from 192.0.2.7 port 51000 ssh2: RSA SHA256:x", ["deploy"]),
    ("Failed password for invalid user oracle from 192.0.2.8 port 2222 ssh2", ["oracle"]),
    ("Failed none for invalid user guest from 192.0.2.8 port 2222 ssh2", ["guest"]),
    ("Invalid user webmaster from 192.0.2.9", ["webmaster"]),
    ("Illegal user test from 192.0.2.9", ["test"]),
    ("input_userauth_request: invalid user ubnt [preauth]", ["ubnt"]),
    ("Disconnected from invalid user admin 192.0.2.10 port 4000 [preauth]", ["admin"]),
    ("Connection closed by authenticating user bob 192.0.2.10 port 4000 [preauth]", ["bob"]),
    ("Disconnecting: Too many authentication failures for root [preauth]", ["root"]),
    ("User carol from 192.0.2.11 not allowed because not listed in AllowUsers", ["carol"]),
    ("pam_unix(sshd:session): session opened for user dave by (uid=0)", ["dave"]),
    ("pam_unix(sshd:session): session closed for user dave", ["dave"]),
    ("pam_unix(su:session): session opened for user root by erin(uid=1000)", ["root", "erin"]),
    (
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=192.0.2.12  user=frank",
        ["frank"],
    ),
    ("sudo:    gina : TTY=pts/0 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls", ["gina", "root"]),
    ("login[812]: LOGIN ON tty1 BY henry", ["henry"]),
    ("login[812]: FAILED LOGIN 1 FROM 192.0.2.13 FOR ivan, Authentication failure", ["ivan"]),
    ("su: (to root) judy on pts/2", ["judy"]),
    ("passwd[90]: pam_unix(passwd:chauthtok): password changed for kate", ["kate"]),
]


@pytest.mark.parametrize(("line", "names"), CASES)
def test_each_documented_format(line: str, names: list[str]) -> None:
    found = LogUsernameDetector().detect(line)
    assert [d.text for d in found] == names
    for d in found:
        assert line[d.start : d.end] == d.text
        assert d.entity_type is EntityType.USERNAME


@pytest.mark.parametrize(
    "line",
    [
        "pam_unix(sshd:auth): check pass; user unknown",
        "Received disconnect from 192.0.2.10: 11: Bye Bye [preauth]",
        "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.12",
        "the user is happy with the new release",
        "Accepted password for ${USER} from 192.0.2.7 port 51000 ssh2",
        "session opened for user root by (uid=0)",  # "root" only; "by (uid=0)" names nobody
    ],
)
def test_no_name_where_the_format_has_none(line: str) -> None:
    names = [d.text for d in LogUsernameDetector().detect(line)]
    assert names in ([], ["root"]) and ("root" in line or names == [])


def test_off_by_default_and_enabled_by_flag_or_type() -> None:
    line = "Invalid user webmaster from 192.0.2.9"
    assert "webmaster" in Redactor().redact(line)
    assert "webmaster" not in Redactor(use_log_usernames=True).redact(line)
    assert "webmaster" not in Redactor(types=["username"]).redact(line)


def test_declared_bounds_keep_the_default_overlap() -> None:
    req = LogUsernameDetector.requirements
    assert req.required_overlap <= 8192
    assert Redactor(use_log_usernames=True).min_safe_overlap == Redactor().min_safe_overlap


def test_streamed_output_equals_whole_document() -> None:
    text = "\n".join(line for line, _ in CASES) * 40
    r = Redactor(use_log_usernames=True, chunk_size=8192)
    whole = r.redact(text)
    for size in (1, 7, 100, 4096):
        chunks = (text[i : i + size] for i in range(0, len(text), size))
        assert "".join(r.redact_stream(chunks)) == whole


def test_cli_flag(tmp_path) -> None:
    from safestream_redactor.cli import main

    src = tmp_path / "auth.log"
    src.write_text("Invalid user webmaster from 192.0.2.9\n", encoding="utf-8")
    dst = tmp_path / "out.log"
    main(["redact", str(src), "-o", str(dst), "--log-usernames"])
    assert "webmaster" not in dst.read_text(encoding="utf-8")


def test_streaming_at_its_own_minimal_overlap() -> None:
    # The tier alone at the smallest overlap its declarations allow: tiny chunks and
    # boundaries inside names and cues must still give the whole-document result.
    from safestream_redactor.engine import required_overlap, stream_windows

    det = LogUsernameDetector()
    w = required_overlap([det])
    text = "\n".join(line for line, _ in CASES) * 3

    def spans(dets, off=0):
        return [(d.start + off, d.end + off, d.text) for d in dets]

    whole = spans(det.detect(text))
    assert all(e - s <= LogUsernameDetector.requirements.max_span for s, e, _t in whole)
    for size in (1, 2, 3, 7, 50):
        out, off = [], 0
        chunks = (text[i : i + size] for i in range(0, len(text), size))
        for segment, dets in stream_windows(chunks, det.detect, w, min_emit=w):
            out += spans(dets, off)
            off += len(segment)
        assert out == whole, f"size={size}"
