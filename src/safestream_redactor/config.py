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

    [plugins]
    enabled = false             # third-party detector plugins are opt-in
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from safestream_redactor.entities import EntityType
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.redactor import Redactor

# A DLP tool must fail closed on misconfiguration: a typo like ``replacment``
# or a stray ``[redation]`` section silently falling back to defaults means
# unredacted output shipping to production. So the schema is a strict allowlist
# and any unknown section or key is a hard error, not a silent default.
#
# Values are type-checked too. TOML has real booleans and numbers, but a policy
# author can still write ``use_entropy = "no"`` (a non-empty string, so truthy:
# the tier stayed ON) or ``min_confidence = "0.5"`` (which crashed mid-stream
# with a TypeError, after partial output had been written to stdout). Each key
# maps to the kind of value it accepts, checked before anything is built.
_BOOL, _INT, _NUMBER, _STR, _STR_LIST, _STR_TABLE = (
    "a boolean",
    "an integer",
    "a number",
    "a string",
    "an array of strings",
    "a table of strings",
)

_SCHEMA: dict[str, dict[str, str]] = {
    "detection": {
        "types": _STR_LIST,
        "min_confidence": _NUMBER,
        "use_ner": _BOOL,
        "ner_model": _STR,
        "use_gazetteer": _BOOL,
        "use_ensemble": _BOOL,
        "semantic_policy": _STR,
        "use_onnx": _BOOL,
        "onnx_model": _STR,
        "onnx_vocab": _STR,
        "onnx_labels": _STR,
        "onnx_min_score": _NUMBER,
        "onnx_batch_size": _INT,
        "use_entropy": _BOOL,
        "use_regional": _BOOL,
        "use_dates": _BOOL,
        "backend": _STR,
    },
    "redaction": {
        "mode": _STR,
        "replacement": _STR,
        "replacements": _STR_TABLE,
        "mask_keep_last": _INT,
        "mask_char": _STR,
        "hmac_key": _STR,
        "pseudonym_length": _INT,
        "hash_algorithm": _STR,
        "hash_salt": _STR,
        "encrypt_key": _STR,
    },
    "custom": {"words": _STR_LIST, "patterns": _STR_LIST},
    "streaming": {"chunk_size": _INT, "overlap": _INT, "allow_unsafe_overlap": _BOOL},
    "calibration": {"model": _STR},
    "plugins": {"enabled": _BOOL},
}


def _closest(name: str, valid: Iterable[str]) -> str:
    """Suggestion hint for a mistyped key, using difflib when it finds a near match."""
    import difflib

    match = difflib.get_close_matches(name, sorted(valid), n=1)
    return f" (did you mean {match[0]!r}?)" if match else ""


def _has_kind(value: object, kind: str) -> bool:
    # bool is an int subclass, so it is excluded explicitly from the numeric kinds
    if kind == _BOOL:
        return isinstance(value, bool)
    if kind == _INT:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == _NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == _STR:
        return isinstance(value, str)
    if kind == _STR_LIST:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    if kind == _STR_TABLE:
        return isinstance(value, dict) and all(isinstance(v, str) for v in value.values())
    raise AssertionError(f"unknown schema kind {kind!r}")  # pragma: no cover


def validate_config(data: dict[str, Any]) -> None:
    """Reject unknown sections/keys and ill-typed values so a bad policy never runs.

    ``redaction.replacements`` is exempt from key checking: its keys are entity
    type names, validated separately when the policy is built.
    """
    for section, keys in data.items():
        if section not in _SCHEMA:
            raise ValueError(
                f"unknown config section [{section}]{_closest(section, _SCHEMA)}; "
                f"valid sections: {', '.join(sorted(_SCHEMA))}"
            )
        if not isinstance(keys, dict):
            raise ValueError(f"config section [{section}] must be a table")
        allowed = _SCHEMA[section]
        for key, value in keys.items():
            if key not in allowed:
                raise ValueError(
                    f"unknown key {key!r} in [{section}]{_closest(key, allowed)}; "
                    f"valid keys: {', '.join(sorted(allowed))}"
                )
            if not _has_kind(value, allowed[key]):
                raise ValueError(
                    f"[{section}] {key} must be {allowed[key]}, "
                    f"got {type(value).__name__} {value!r}"
                )


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and validate a TOML policy file. Raises ``ValueError`` if it is invalid."""
    try:
        with open(path, "rb") as f:
            data: dict[str, Any] = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {os.fspath(path)!r}: {exc}") from exc
    validate_config(data)
    return data


def policy_kwargs_from_config(data: dict[str, Any]) -> dict[str, Any]:
    """:class:`RedactionPolicy` keyword arguments for the ``[redaction]`` section.

    Only keys present in the file are returned, so callers (the CLI) can overlay
    their own values before the policy is built and validated exactly once.
    """
    section = dict(data.get("redaction", {}))
    if "replacements" in section:
        section["replacements"] = {
            EntityType.from_name(k): v for k, v in section["replacements"].items()
        }
    return section


def policy_from_config(data: dict[str, Any]) -> RedactionPolicy:
    return RedactionPolicy(**policy_kwargs_from_config(data))


def redactor_kwargs_from_config(
    data: dict[str, Any], *, base_dir: str | os.PathLike[str] = "."
) -> dict[str, Any]:
    """:class:`Redactor` keyword arguments for a validated config (minus ``policy``).

    Only keys present in the file are returned; everything else keeps the
    constructor's default. ``base_dir`` anchors relative paths in
    ``[calibration]`` so a policy stays portable with the model it references.
    """
    detection = data.get("detection", {})
    custom = data.get("custom", {})
    kwargs: dict[str, Any] = dict(detection)
    if "words" in custom:
        kwargs["custom_words"] = custom["words"]
    if "patterns" in custom:
        kwargs["custom_patterns"] = custom["patterns"]
    kwargs.update(data.get("streaming", {}))
    if "enabled" in data.get("plugins", {}):
        kwargs["load_plugins"] = data["plugins"]["enabled"]
    model_path = data.get("calibration", {}).get("model")
    if model_path:
        from safestream_redactor.calibration import Calibrator

        kwargs["calibrator"] = Calibrator.load(os.path.join(os.fspath(base_dir), model_path))
    return kwargs


def redactor_from_config(path: str | os.PathLike[str]) -> Redactor:
    """Build a fully configured :class:`Redactor` from a TOML policy file."""
    data = load_config(path)
    return Redactor(
        policy=policy_from_config(data),
        **redactor_kwargs_from_config(data, base_dir=os.path.dirname(os.fspath(path))),
    )
