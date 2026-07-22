"""Command-line interface.

Examples::

    safestream redact input.txt -o out.txt --types email,ssn --replace "***"
    safestream redact big.log -o clean.log --custom-word "ProjectX" --custom-word "Jane Doe"
    safestream redact secrets.env -o - --mode mask --keep-last 4
    cat input.txt | safestream redact - -o -
    safestream detect input.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator

from safestream_redactor import __version__
from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
from safestream_redactor.entities import EntityType
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.redactor import Redactor


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safestream",
        description="Streaming PII & credential redaction with constant memory usage.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("input", help="input file path, or '-' for stdin")
    common.add_argument(
        "--types",
        help="comma-separated entity types to detect (default: all), "
        f"choices: {', '.join(e.value for e in EntityType)}",
    )
    common.add_argument("--config", help="TOML policy file (CLI flags override it)")
    common.add_argument(
        "--custom-word",
        action="append",
        default=[],
        metavar="WORD",
        help="literal word/phrase to always redact (repeatable)",
    )
    common.add_argument(
        "--custom-regex",
        action="append",
        default=[],
        metavar="REGEX",
        help="regex whose matches are always redacted (repeatable)",
    )
    common.add_argument("--min-confidence", type=float, default=None)
    common.add_argument("--ner", action="store_true", help="enable the spaCy NER tier")
    common.add_argument("--chunk-size", type=int, default=None, metavar="BYTES")
    common.add_argument("--overlap", type=int, default=None, metavar="CHARS")

    redact = sub.add_parser("redact", parents=[common], help="redact a file or stdin")
    redact.add_argument("-o", "--output", required=True, help="output path, or '-' for stdout")
    redact.add_argument(
        "--mode",
        choices=["replace", "mask", "pseudonymize"],
        default=None,
        help="redaction mode (default: replace)",
    )
    redact.add_argument("--replace", default=None, metavar="TEXT", help="replacement string")
    redact.add_argument(
        "--replace-type",
        action="append",
        default=[],
        metavar="TYPE=TEXT",
        help="per-type replacement, e.g. --replace-type email='<EMAIL>' (repeatable)",
    )
    redact.add_argument("--keep-last", type=int, default=None, help="mask mode: chars to keep")
    redact.add_argument("--mask-char", default=None)
    redact.add_argument("--hmac-key", default=None, help="secret for pseudonymize mode")

    detect = sub.add_parser("detect", parents=[common], help="list detections without redacting")
    detect.add_argument("--json", action="store_true", help="one JSON object per detection")
    return parser


def _build_redactor(args: argparse.Namespace) -> Redactor:
    if args.config:
        from safestream_redactor.config import load_config, policy_from_config, redactor_from_config

        redactor = redactor_from_config(args.config)
        policy = policy_from_config(load_config(args.config))
    else:
        redactor = None
        policy = RedactionPolicy()

    # CLI flags override the config file
    if getattr(args, "mode", None):
        policy.mode = policy.mode.__class__(args.mode)
    if getattr(args, "replace", None) is not None:
        policy.replacement = args.replace
    if getattr(args, "keep_last", None) is not None:
        policy.mask_keep_last = args.keep_last
    if getattr(args, "mask_char", None) is not None:
        policy.mask_char = args.mask_char
    if getattr(args, "hmac_key", None) is not None:
        policy.hmac_key = args.hmac_key.encode()
    for spec in getattr(args, "replace_type", []):
        type_name, _, replacement = spec.partition("=")
        if not _:
            raise SystemExit(f"--replace-type expects TYPE=TEXT, got {spec!r}")
        policy.replacements[EntityType.from_name(type_name)] = replacement
    if policy.mode.value == "pseudonymize" and not policy.hmac_key:
        raise SystemExit("--mode pseudonymize requires --hmac-key")

    if redactor is None:
        types = args.types.split(",") if args.types else None
        return Redactor(
            types=types,
            policy=policy,
            min_confidence=args.min_confidence if args.min_confidence is not None else 0.5,
            custom_words=args.custom_word,
            custom_patterns=args.custom_regex,
            use_ner=args.ner,
            chunk_size=args.chunk_size or DEFAULT_CHUNK_SIZE,
            overlap=args.overlap if args.overlap is not None else DEFAULT_OVERLAP,
        )

    # config file provided: overlay any explicitly passed flags
    redactor.policy = policy
    if args.types:
        from safestream_redactor.detectors.deterministic import DeterministicDetector

        redactor._detectors[0] = DeterministicDetector(
            [EntityType.from_name(t) for t in args.types.split(",")]
        )
    if args.min_confidence is not None:
        redactor.min_confidence = args.min_confidence
    if args.custom_word or args.custom_regex:
        from safestream_redactor.detectors.custom import CustomDetector

        redactor._detectors.insert(1, CustomDetector(args.custom_word, args.custom_regex))
    if args.chunk_size:
        redactor.chunk_size = args.chunk_size
    if args.overlap is not None:
        redactor.overlap = args.overlap
    return redactor


def _input_chunks(path: str, chunk_size: int) -> Iterator[str]:
    if path == "-":
        while chunk := sys.stdin.read(chunk_size):
            yield chunk
    else:
        from safestream_redactor.engine import read_chunks

        yield from read_chunks(path, chunk_size)


def _cmd_redact(args: argparse.Namespace) -> int:
    redactor = _build_redactor(args)
    chunks = _input_chunks(args.input, redactor.chunk_size)
    if args.output == "-":
        for piece in redactor.redact_stream(chunks):
            sys.stdout.write(piece)
        sys.stdout.flush()
    elif args.input == "-":
        with open(args.output, "w", encoding="utf-8") as out:
            for piece in redactor.redact_stream(chunks):
                out.write(piece)
    else:
        redactor.redact_file(args.input, args.output)
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    redactor = _build_redactor(args)
    count = 0
    offset = 0
    for segment, detections in redactor.detect_stream(
        _input_chunks(args.input, redactor.chunk_size)
    ):
        for det in detections:
            count += 1
            if args.json:
                print(
                    json.dumps(
                        {
                            "type": det.entity_type.value,
                            "start": offset + det.start,
                            "end": offset + det.end,
                            "text": det.text,
                            "confidence": round(det.confidence, 3),
                            "source": det.source,
                        }
                    )
                )
            else:
                print(f"{det.entity_type.value:>13}  conf={det.confidence:.2f}  {det.text!r}")
        offset += len(segment)
    if not args.json:
        print(f"-- {count} detection(s)", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "redact":
            return _cmd_redact(args)
        return _cmd_detect(args)
    except (OSError, ValueError) as exc:
        print(f"safestream: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
