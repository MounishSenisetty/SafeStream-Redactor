"""TOML config file support for redaction policies.

Example policy file::

    [detection]
    types = ["email", "ssn", "credit_card"]
    min_confidence = 0.5
    use_ner = false

    [redaction]
    mode = "replace"            # replace | mask | pseudonymize
    replacement = "[REDACTED]"
    mask_keep_last = 4
    mask_char = "*"
    # hmac_key = "change-me"    # required for pseudonymize

    [redaction.replacements]
    email = "<EMAIL>"

    [custom]
    words = ["ProjectX"]
    patterns = ['\\binternal-[a-z]+\\b']

    [streaming]
    chunk_size = 65536
    overlap = 4096
"""

from __future__ import annotations

import os
import sys
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
from safestream_redactor.entities import EntityType
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.redactor import Redactor


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    with open(path, "rb") as f:
        data: dict[str, Any] = tomllib.load(f)
    return data


def policy_from_config(data: dict[str, Any]) -> RedactionPolicy:
    section = data.get("redaction", {})
    hmac_key = section.get("hmac_key")
    return RedactionPolicy(
        mode=section.get("mode", "replace"),
        replacement=section.get("replacement", "[REDACTED]"),
        replacements={
            EntityType.from_name(k): v for k, v in section.get("replacements", {}).items()
        },
        mask_keep_last=section.get("mask_keep_last", 4),
        mask_char=section.get("mask_char", "*"),
        hmac_key=hmac_key.encode() if isinstance(hmac_key, str) else hmac_key,
    )


def redactor_from_config(path: str | os.PathLike[str]) -> Redactor:
    """Build a fully configured :class:`Redactor` from a TOML policy file."""
    data = load_config(path)
    detection = data.get("detection", {})
    custom = data.get("custom", {})
    streaming = data.get("streaming", {})
    return Redactor(
        types=detection.get("types"),
        policy=policy_from_config(data),
        min_confidence=detection.get("min_confidence", 0.5),
        custom_words=custom.get("words", ()),
        custom_patterns=custom.get("patterns", ()),
        use_ner=detection.get("use_ner", False),
        ner_model=detection.get("ner_model", "en_core_web_sm"),
        chunk_size=streaming.get("chunk_size", DEFAULT_CHUNK_SIZE),
        overlap=streaming.get("overlap", DEFAULT_OVERLAP),
    )
