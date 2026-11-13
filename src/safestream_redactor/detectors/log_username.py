"""User names in authentication log messages (opt-in).

A user name in a log line has no shape of its own: ``webmaster``, ``admin`` or
``oracle`` look like any other word. What identifies it is the fixed text the
logging program writes around it. This tier matches the message formats of the
programs that log authentication: OpenSSH's ``sshd``, Linux-PAM's ``pam_unix``,
``su``, ``sudo`` and ``login``. It redacts only the name, never the surrounding
text.

The patterns follow the formats those programs document and print, for example
OpenSSH's ``Accepted %s for %s from %s port %d`` and ``Invalid user %s from %s``,
pam_unix's ``authentication failure; logname= uid= euid= tty= ruser= rhost= user=``
and ``session opened for user %s by %s(uid=%d)``, and sudo's
``alice : TTY=pts/0 ; PWD=... ; USER=root ; COMMAND=...``. They were not derived
from any evaluation corpus.

Off by default: it redacts names in lines that many operators keep for incident
response. Enable it with ``use_log_usernames=True`` (or ``--log-usernames``), or by
naming ``username`` in ``types``.

Streaming safety: each pattern starts at its cue, at most ``_LEFT`` characters
before the name, and needs at most ``_RIGHT`` characters after it (a host name
and a short literal), so every match lies inside one detection window. The
detector is stateless, and it declares these bounds.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements, is_placeholder
from safestream_redactor.entities import Detection, EntityType

_MAX_NAME = 64
_LEFT = 96  # longest cue before a name, e.g. "Failed keyboard-interactive/pam for invalid user "
_RIGHT = 320  # " from <host> not allowed because ...": a DNS name is at most 253 characters

# a user name as these programs print it: no whitespace; PAM and su also stop at "("
_NAME = r"(?P<u>[^\s(]{1,64})"
_NAME_KV = r"(?P<u>[^\s;,]{1,64})"  # key=value forms end at ";" (sudo) or ","

_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        # OpenSSH: Accepted/Failed <method> for [invalid user] <name> from <host>
        rf"\b(?:Accepted|Failed|Postponed|Partial) \S+ for"
        rf" (?:invalid user |illegal user )?{_NAME} from ",
        # OpenSSH: Invalid user <name> from <host> (Illegal user in older releases)
        rf"\b(?:Invalid|Illegal) user {_NAME} from ",
        # OpenSSH: input_userauth_request: invalid user <name> [preauth]
        rf"\binput_userauth_request: (?:invalid|illegal) user {_NAME}(?= |$)",
        # OpenSSH 7.x+: "Disconnected from" / "Connection closed by"
        # [invalid|authenticating] user <name> <host>
        rf"\b(?:Disconnected from|Connection closed by|Connection reset by"
        rf"|Received disconnect from)"
        rf" (?:invalid |authenticating )?user {_NAME} ",
        # OpenSSH: Too many authentication failures for [invalid user] <name>
        rf"\bToo many authentication failures for (?:invalid user )?{_NAME}(?= |$)",
        # OpenSSH: User <name> from <host> not allowed because ...
        rf"\bUser {_NAME} from \S{{1,253}} not allowed\b",
        # OpenSSH: Failed password for <name> from ... in "message repeated N times: [ ... ]"
        # is covered by the first pattern. PAM: session opened/closed for user <name>
        rf"\bsession (?:opened|closed) for user {_NAME}(?=[ (]|$)",
        # PAM / su: ... by <name>(uid=N)
        rf"\bby {_NAME}\(uid=\d+\)",
        # PAM: authentication failure; logname=<a> ... ruser=<b> ... user=<c>; sudo: USER=<name>
        rf"(?<![\w.-])(?:logname|ruser|user|USER)={_NAME_KV}",
        # sudo: "sudo: alice : TTY=pts/0 ; ..."
        rf"\bsudo(?:\[\d+\])?:\s+{_NAME} : (?:TTY|PWD|USER|COMMAND)=",
        # login: LOGIN ON tty1 BY <name>; FAILED LOGIN n FROM <host> FOR <name>, ...
        rf"\bLOGIN ON \S+ BY {_NAME}(?= |$)",
        rf"\bFAILED LOGIN \(?\d+\)? (?:ON \S+ )?FROM \S+ FOR {_NAME_KV}",
        # su (classic): "(to root) alice on pts/0" and pam_unix: password changed for <name>
        rf"\(to [^\s)]{{1,64}}\) {_NAME} on ",
        rf"\bpassword changed for {_NAME}(?= |$)",
    )
)

# words the formats put where a name usually goes, which are not names
_NOT_NAMES = frozenset({"unknown", "(unknown)", "user", "invalid", "illegal", "by", "for"})


class LogUsernameDetector:
    """Redact user names in sshd, PAM, su, sudo and login messages."""

    name = "log_username"
    requirements = StreamingRequirements(
        max_span=_MAX_NAME, left_context=_LEFT, right_context=_RIGHT
    )

    def detect(self, text: str) -> list[Detection]:
        found: dict[tuple[int, int], Detection] = {}
        for pattern in _PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.span("u")
                value = m.group("u").rstrip(".,:;]")
                end = start + len(value)
                if (
                    not value
                    or start - m.start() > _LEFT
                    or value.lower() in _NOT_NAMES
                    or is_placeholder(value)
                ):
                    continue
                found.setdefault(
                    (start, end),
                    Detection(start, end, value, EntityType.USERNAME, 0.9, source=self.name),
                )
        return sorted(found.values(), key=lambda d: (d.start, d.end))
