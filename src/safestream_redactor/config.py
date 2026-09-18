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
    overlap = 8192
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

# A DLP tool must fail closed on misconfiguration: a typo like ``replacment``
# or a stray ``[redation]`` section silently falling back to defaults means
# unredacted output shipping to production. So the schema is a strict allowlist
# and any unknown section or key is a hard error, not a silent default.
_SCHEMA: dict[str, set[str]] = {
    "detection": {
        "types",
        "min_confidence",
        "use_ner",
        "ner_model",
        "use_onnx",
        "onnx_model",
        "onnx_vocab",
        "onnx_labels",
        "onnx_min_score",
        "use_entropy",
    },
    "redaction": {
        "mode",
        "replacement",
        "replacements",
        "mask_keep_last",
        "mask_char",
        "hmac_key",
        "pseudonym_length",
    },
    "custom": {"words", "patterns"},
    "streaming": {"chunk_size", "overlap", "allow_unsafe_overlap"},
    "calibration": {"model"},
}


def _closest(name: str, valid: set[str]) -> str:
    """Suggestion hint for a mistyped key, using difflib when it finds a near match."""
    import difflib

    match = difflib.get_close_matches(name, sorted(valid), n=1)
    return f" (did you mean {match[0]!r}?)" if match else ""


def validate_config(data: dict[str, Any]) -> None:
    """Reject unknown sections/keys so a misconfigured policy never runs silently.

    ``redaction.replacements`` is exempt from key checking: its keys are entity
    type names, validated separately when the policy is built.
    """
    for section, keys in data.items():
        if section not in _SCHEMA:
            raise ValueError(
                f"unknown config section [{section}]{_closest(section, set(_SCHEMA))}; "
                f"valid sections: {', '.join(sorted(_SCHEMA))}"
            )
        if not isinstance(keys, dict):
            raise ValueError(f"config section [{section}] must be a table")
        allowed = _SCHEMA[section]
        for key in keys:
            if key not in allowed:
                raise ValueError(
                    f"unknown key {key!r} in [{section}]{_closest(key, allowed)}; "
                    f"valid keys: {', '.join(sorted(allowed))}"
                )


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    with open(path, "rb") as f:
        data: dict[str, Any] = tomllib.load(f)
    validate_config(data)
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
        pseudonym_length=section.get("pseudonym_length", 16),
    )


def redactor_from_config(path: str | os.PathLike[str]) -> Redactor:
    """Build a fully configured :class:`Redactor` from a TOML policy file."""
    data = load_config(path)
    detection = data.get("detection", {})
    custom = data.get("custom", {})
    streaming = data.get("streaming", {})
    calibration = data.get("calibration", {})
    calibrator = None
    model_path = calibration.get("model")
    if model_path:
        from safestream_redactor.calibration import Calibrator

        # resolve the model path relative to the config file, so a policy is
        # portable together with the model it references
        model_path = os.path.join(os.path.dirname(os.fspath(path)), model_path)
        calibrator = Calibrator.load(model_path)
    return Redactor(
        types=detection.get("types"),
        policy=policy_from_config(data),
        min_confidence=detection.get("min_confidence", 0.5),
        custom_words=custom.get("words", ()),
        custom_patterns=custom.get("patterns", ()),
        use_ner=detection.get("use_ner", False),
        ner_model=detection.get("ner_model", "en_core_web_sm"),
        use_onnx=detection.get("use_onnx", False),
        onnx_model=detection.get("onnx_model"),
        onnx_vocab=detection.get("onnx_vocab"),
        onnx_labels=detection.get("onnx_labels"),
        onnx_min_score=detection.get("onnx_min_score", 0.5),
        use_entropy=detection.get("use_entropy", True),
        calibrator=calibrator,
        chunk_size=streaming.get("chunk_size", DEFAULT_CHUNK_SIZE),
        overlap=streaming.get("overlap", DEFAULT_OVERLAP),
        allow_unsafe_overlap=streaming.get("allow_unsafe_overlap", False),
    )
