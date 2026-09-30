"""Command-line interface.

Examples::

    safestream redact input.txt -o out.txt --types email,ssn --replace "***"
    safestream redact big.log -o clean.log --custom-word "ProjectX" --custom-word "Jane Doe"
    safestream redact secrets.env -o - --mode mask --keep-last 4
    cat input.txt | safestream redact - -o -
    safestream detect . --fail-on-detect            # CI gate: file:line:col, never the secret
    safestream detect input.txt --json --show-text  # local triage: include matched text
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from safestream_redactor import __version__
from safestream_redactor.entities import EntityType
from safestream_redactor.locate import LineTracker
from safestream_redactor.policy import RedactionPolicy
from safestream_redactor.redactor import Redactor
from safestream_redactor.report import RedactionStats


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safestream",
        description="Streaming PII & credential redaction with constant memory usage.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    # The input positional is added per-subcommand: `redact` takes exactly one,
    # `detect` takes one or more (so it works as a pre-commit hook over staged
    # files). Shared flags live here.
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
    common.add_argument(
        "--onnx",
        metavar="MODEL.onnx",
        default=None,
        help="enable the local ONNX NER tier with this model (requires the [onnx] "
        "extra and --onnx-vocab); runs on-device, no data egress",
    )
    common.add_argument(
        "--onnx-vocab",
        metavar="VOCAB.json",
        default=None,
        help="JSON token->id vocab for the ONNX tier (required with --onnx)",
    )
    common.add_argument(
        "--onnx-labels",
        metavar="LABELS.json",
        default=None,
        help="JSON id->tag map for the ONNX tier (default: CoNLL IOB2 scheme)",
    )
    common.add_argument(
        "--onnx-min-score",
        type=float,
        default=0.5,
        help="drop ONNX detections below this model probability (default: 0.5)",
    )
    common.add_argument(
        "--no-entropy",
        dest="entropy",
        action="store_false",
        default=True,
        help="disable the high-entropy secret detector (on by default)",
    )
    common.add_argument("--chunk-size", type=int, default=None, metavar="BYTES")
    common.add_argument("--overlap", type=int, default=None, metavar="CHARS")
    common.add_argument(
        "--allow-unsafe-overlap",
        action="store_true",
        help="permit an --overlap below the detectors' safe minimum (fail-open); "
        "by default a too-small overlap is rejected to avoid boundary-induced leaks",
    )
    common.add_argument(
        "--memory-limit",
        default=None,
        metavar="SIZE",
        help="run within an explicit application memory budget (e.g. 32MB, 256MiB). "
        "Caps worker count to stay under the budget, refuses configs that cannot "
        "fit (exit 3), and on Linux/POSIX backs the budget with a hard RLIMIT_AS "
        "cap so an over-allocating run fails closed at the kernel (also exit 3) "
        "rather than swelling past the limit.",
    )
    common.add_argument(
        "--encoding",
        default="utf-8",
        metavar="ENC",
        help="text encoding of the input/output (default: utf-8)",
    )
    common.add_argument(
        "--enable-plugins",
        action="store_true",
        help="load third-party detector plugins (entry-point group "
        "'safestream_redactor.detectors'); off by default because plugin code runs "
        "with full privileges. Also settable as [plugins] enabled = true",
    )
    common.add_argument(
        "--allow-network",
        dest="offline_guard",
        action="store_false",
        default=True,
        help="disable the offline network guard (allowed by default: any outbound "
        "non-loopback connection is blocked while redacting)",
    )
    common.add_argument(
        "--offline-hard",
        choices=["seccomp", "netns", "auto"],
        default=None,
        metavar="MODE",
        help="opt-in kernel-enforced offline mode for redact/detect, in addition to "
        "the default in-process guard (Linux only): 'seccomp' blocks AF_INET/AF_INET6 "
        "socket creation process-wide (native code included); 'netns' enters an empty "
        "network namespace (no network at all, loopback included); 'auto' tries netns "
        "then seccomp. Applied before workers fork. Falls back with a warning where "
        "unsupported. Not for serve/mcp-serve (they need loopback).",
    )

    redact = sub.add_parser("redact", parents=[common], help="redact a file or stdin")
    redact.add_argument("input", help="input file path, directory, or '-' for stdin")
    redact.add_argument("-o", "--output", required=True, help="output path, or '-' for stdout")
    redact.add_argument(
        "--stats",
        action="store_true",
        help="print per-type detection counts to stderr when done",
    )
    redact.add_argument(
        "--report",
        metavar="FILE",
        help="write a JSON run report (counts and sizes only, never matched text)",
    )
    redact.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="parallel workers: RAM/CPU-aware fan-out over files when INPUT is a "
        "directory, or range-parallel redaction of one large file (output is "
        "byte-identical to the sequential pass)",
    )
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
    detect.add_argument(
        "input",
        nargs="+",
        help="one or more files or directories, or '-' for stdin (accepts many so it "
        "works as a pre-commit/CI secret gate; directories are walked recursively, "
        "skipping symlinks, .git/.hg/.svn, and binary files)",
    )
    detect.add_argument("--json", action="store_true", help="one JSON object per detection")
    detect.add_argument(
        "--show-text",
        "--reveal-matches",
        dest="show_text",
        action="store_true",
        help="also print the matched text (hidden by default so a found secret is never "
        "copied into logs). For local triage only; never use it in CI or hooks",
    )
    detect.add_argument(
        "--sarif",
        action="store_true",
        help="emit a SARIF 2.1.0 report (for GitHub code scanning / CI); content-free",
    )
    detect.add_argument(
        "--fail-on-detect",
        action="store_true",
        help="exit with status 1 if anything is detected (CI/pre-commit secret gate)",
    )

    init = sub.add_parser("init-config", help="write a documented, valid starter policy TOML file")
    init.add_argument(
        "-o", "--output", default="-", help="output path, or '-' for stdout (default)"
    )
    init.add_argument(
        "--force", action="store_true", help="overwrite the output file if it already exists"
    )

    serve = sub.add_parser("serve", help="run a local REST API (stdlib only) around the redactor")
    serve.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, loopback)"
    )
    serve.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    serve.add_argument("--config", help="TOML policy file used for every request")
    serve.add_argument(
        "--enable-plugins", action="store_true", help="load third-party detector plugins"
    )
    serve.add_argument(
        "--max-body",
        type=int,
        default=None,
        metavar="BYTES",
        help="reject request bodies larger than this (default: 8 MiB)",
    )

    mcp = sub.add_parser(
        "mcp-serve",
        help="run a local Model Context Protocol server (stdio) exposing scan/redact tools",
    )
    mcp.add_argument("--config", help="TOML policy file used for every tool call")
    mcp.add_argument(
        "--enable-plugins", action="store_true", help="load third-party detector plugins"
    )

    ui = sub.add_parser(
        "ui",
        help="open the local web playground (Streamlit; needs the [ui] extra)",
        description="Start the detection/redaction playground in your browser. Runs "
        "Streamlit bound to loopback with usage telemetry off and the offline guard on.",
    )
    ui.add_argument(
        "--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, loopback)"
    )
    ui.add_argument("--port", type=int, default=8501, help="bind port (default: 8501)")
    ui.add_argument(
        "--headless", action="store_true", help="do not open a browser window automatically"
    )
    return parser


# A starter policy that documents every option and passes validate_config as-is.
# Keys mirror the config schema exactly, so this doubles as executable documentation.
_STARTER_CONFIG = """\
# SafeStream-Redactor policy file. Pass it with:  safestream redact IN -o OUT --config this.toml
# CLI flags override anything set here. Unknown keys/sections are rejected (fail-closed).

[detection]
# types = ["email", "ssn", "credit_card"]   # omit for all types
min_confidence = 0.5
use_ner = false                             # requires the [ner] extra + a model
# ner_model = "en_core_web_sm"
use_onnx = false                            # local ONNX NER tier ([onnx] extra, on-device)
# onnx_model = "model.onnx"                 # required when use_onnx = true
# onnx_vocab = "vocab.json"                 # required when use_onnx = true (token->id)
# onnx_labels = "labels.json"               # optional id->tag (default: CoNLL IOB2)
# onnx_min_score = 0.5
use_entropy = true                          # high-entropy secret detection
# use_gazetteer = false                     # dictionary-backed person-name tier (no deps)
# use_ensemble = false                      # semantic PERSON/ORG ensemble (no deps)
# semantic_policy = "strict"                # ensemble policy: strict | high_recall
# backend = "python"                        # python | native | auto ([native] extra)

[redaction]
mode = "replace"                            # replace | mask | pseudonymize
replacement = "[REDACTED]"
mask_keep_last = 4                          # mask mode: trailing chars left visible
mask_char = "*"
# hmac_key = "change-me"                    # required for pseudonymize (keep it secret)
# pseudonym_length = 16                     # hex digits of the keyed token (8-64)

[redaction.replacements]                    # optional per-type replacement strings
# email = "<EMAIL>"

[custom]
# words = ["ProjectX"]                      # literal words/phrases to always redact
# patterns = ['\\\\binternal-[a-z]+\\\\b']       # regexes whose matches are always redacted

[streaming]
chunk_size = 65536
overlap = 8192

[plugins]
enabled = false                             # load third-party detector plugins (trusted only)
"""


def _cmd_init_config(args: argparse.Namespace) -> int:
    # sanity: the emitted template must satisfy the strict validator
    from safestream_redactor.config import validate_config

    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib
    validate_config(tomllib.loads(_STARTER_CONFIG))

    if args.output == "-":
        sys.stdout.write(_STARTER_CONFIG)
        return 0
    if os.path.exists(args.output) and not args.force:
        raise SystemExit(f"{args.output} already exists (pass --force to overwrite)")
    _atomic_write_stream(args.output, iter([_STARTER_CONFIG]), "utf-8")
    print(f"-- wrote starter policy to {args.output}", file=sys.stderr)
    return 0


def _build_redactor(args: argparse.Namespace) -> Redactor:
    """Build the run's :class:`Redactor`: config file first, CLI flags on top.

    Both layers are merged into one set of constructor arguments and the
    redactor is built exactly once, so every flag means the same thing with or
    without ``--config`` and every constructor-side check (entity types, policy
    and streaming validation, the overlap-safety guard) runs on the final
    configuration rather than an intermediate one.
    """
    kwargs: dict[str, Any] = {}
    policy_kwargs: dict[str, Any] = {}
    if args.config:
        from safestream_redactor.config import (
            load_config,
            policy_kwargs_from_config,
            redactor_kwargs_from_config,
        )

        data = load_config(args.config)
        policy_kwargs = policy_kwargs_from_config(data)
        kwargs = redactor_kwargs_from_config(data, base_dir=os.path.dirname(args.config))

    # policy flags (redact only; `detect` has none of these)
    for flag, key in (
        ("mode", "mode"),
        ("replace", "replacement"),
        ("keep_last", "mask_keep_last"),
        ("mask_char", "mask_char"),
        ("hmac_key", "hmac_key"),
    ):
        value = getattr(args, flag, None)
        if value is not None:
            policy_kwargs[key] = value
    replacements = dict(policy_kwargs.get("replacements", {}))
    for spec in getattr(args, "replace_type", []):
        type_name, sep, replacement = spec.partition("=")
        if not sep:
            raise SystemExit(f"--replace-type expects TYPE=TEXT, got {spec!r}")
        replacements[EntityType.from_name(type_name)] = replacement
    if replacements:
        policy_kwargs["replacements"] = replacements
    if policy_kwargs.get("mode") == "pseudonymize" and not policy_kwargs.get("hmac_key"):
        raise SystemExit("--mode pseudonymize requires --hmac-key")
    if args.onnx and not args.onnx_vocab:
        raise SystemExit("--onnx requires --onnx-vocab (a JSON token->id vocab)")

    # detection / streaming flags: scalars override the config, custom words and
    # patterns add to it, and boolean switches only ever turn their tier on
    # (--ner, --onnx) or off (--no-entropy) relative to the config
    if args.types:
        kwargs["types"] = args.types.split(",")
    if args.min_confidence is not None:
        kwargs["min_confidence"] = args.min_confidence
    if args.custom_word:
        kwargs["custom_words"] = [*kwargs.get("custom_words", ()), *args.custom_word]
    if args.custom_regex:
        kwargs["custom_patterns"] = [*kwargs.get("custom_patterns", ()), *args.custom_regex]
    if args.ner:
        kwargs["use_ner"] = True
    if args.onnx:
        kwargs.update(
            use_onnx=True,
            onnx_model=args.onnx,
            onnx_vocab=args.onnx_vocab,
            onnx_labels=args.onnx_labels,
            onnx_min_score=args.onnx_min_score,
        )
    if not args.entropy:
        kwargs["use_entropy"] = False
    if args.chunk_size is not None:
        kwargs["chunk_size"] = args.chunk_size
    if args.overlap is not None:
        kwargs["overlap"] = args.overlap
    if args.allow_unsafe_overlap:
        kwargs["allow_unsafe_overlap"] = True
    if args.enable_plugins:
        kwargs["load_plugins"] = True
    return Redactor(policy=RedactionPolicy(**policy_kwargs), **kwargs)


def _server_redactor(args: argparse.Namespace) -> Redactor:
    """The redactor behind ``serve``/``mcp-serve``: the policy file plus ``--enable-plugins``."""
    if not args.config:
        return Redactor(load_plugins=args.enable_plugins)
    from safestream_redactor.config import (
        load_config,
        policy_from_config,
        redactor_kwargs_from_config,
    )

    data = load_config(args.config)
    kwargs = redactor_kwargs_from_config(data, base_dir=os.path.dirname(args.config))
    if args.enable_plugins:
        kwargs["load_plugins"] = True
    return Redactor(policy=policy_from_config(data), **kwargs)


def _plan_budget(args: argparse.Namespace, redactor: Redactor) -> int | None:
    """Admit the run under ``--memory-limit`` and return the permitted worker cap.

    Returns ``None`` when no budget was requested. Raises
    :class:`~safestream_redactor.memory_budget.ResourceExhaustionError` (caught
    in :func:`main`) when even one worker cannot fit — the fail-closed path.
    """
    limit = getattr(args, "memory_limit", None)
    if not limit:
        return None
    from safestream_redactor.memory_budget import (
        MemoryBudget,
        enforce_address_space_limit,
        estimate_interpreter_baseline,
        format_size,
    )

    _has_model = getattr(args, "ner", False) or getattr(args, "onnx", None)
    budget = MemoryBudget(limit, model_budget="512MB" if _has_model else 0)
    requested = getattr(args, "workers", None)
    plan = budget.plan(
        redactor.chunk_size,
        redactor.overlap,
        requested_workers=requested,
        max_workers=os.cpu_count() or 1,
    )
    baseline = estimate_interpreter_baseline()
    if baseline > budget.limit:
        print(
            f"safestream: warning: the interpreter already resides in "
            f"{format_size(baseline)}, above the {format_size(budget.limit)} budget; "
            "the budget bounds the streaming working set, not total process RSS "
            "(see docs/MEMORY_ARCHITECTURE.md)",
            file=sys.stderr,
        )
    print(
        f"-- memory budget {format_size(budget.limit)}: "
        f"{plan.workers} worker(s) x ~{format_size(plan.per_worker_bytes)} working set, "
        f"headroom ~{format_size(plan.headroom_bytes)}",
        file=sys.stderr,
    )
    # Back the admitted budget with a hard kernel cap on this (orchestrating /
    # streaming) process. Workers get their own per-worker cap when the parallel
    # path runs; see _cmd_redact.
    enforced = enforce_address_space_limit(budget.limit)
    if enforced.applied:
        print(
            f"-- memory limit enforced by kernel (RLIMIT_AS): {enforced.reason}; "
            "over-allocation fails closed (exit 3)",
            file=sys.stderr,
        )
    else:
        print(
            f"safestream: warning: kernel memory enforcement unavailable "
            f"({enforced.reason}); using admission control only (the budget still "
            "sizes workers and refuses configs that cannot fit)",
            file=sys.stderr,
        )
    # Stash the per-worker growth allowance so the parallel dispatch can cap each
    # worker process at the kernel level too.
    args._per_worker_bytes = plan.per_worker_bytes
    return plan.workers


def _atomic_write_stream(path: str, pieces: Iterator[str], encoding: str) -> None:
    """Stream output into ``path`` atomically (same durability as ``redact_file``).

    A crash mid-stream can't leave a truncated file that looks fully redacted.
    """
    from safestream_redactor._atomic import atomic_output

    with atomic_output(path, encoding=encoding) as out:
        for piece in pieces:
            out.write(piece)


def _write_stdout(pieces: Iterator[str], encoding: str) -> None:
    """Write output to stdout in ``encoding`` with line endings untouched."""
    sys.stdout.flush()
    raw = getattr(sys.stdout, "buffer", None)
    for piece in pieces:
        if raw is None:
            sys.stdout.write(piece)
        else:
            raw.write(piece.encode(encoding))
    (raw or sys.stdout).flush()


def _input_chunks(path: str, chunk_size: int, encoding: str = "utf-8") -> Iterator[str]:
    if path == "-":
        raw = getattr(sys.stdin, "buffer", None)
        if raw is None:  # a text-only stand-in (e.g. io.StringIO in embedding code)
            while chunk := sys.stdin.read(chunk_size):
                yield chunk
            return
        # Decode stdin bytes exactly like a file: the requested --encoding (not
        # the locale's), errors="replace", and no newline translation.
        import codecs

        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        while data := raw.read(chunk_size):
            if text := decoder.decode(data):
                yield text
        if tail := decoder.decode(b"", True):
            yield tail
    else:
        from safestream_redactor.engine import read_chunks

        yield from read_chunks(path, chunk_size, encoding)


def _finish_run(
    args: argparse.Namespace, stats: RedactionStats, *, files: int, started: float
) -> None:
    """Emit the optional stats summary and JSON run report for a redact run."""
    if getattr(args, "stats", False):
        print(f"-- {stats.summary()}", file=sys.stderr)
    # An undecodable-bytes warning is always shown (not gated on --stats): it
    # means some input was never scanned, which is a redaction-coverage risk.
    if stats.decode_replacements:
        print(
            f"safestream: warning: {stats.decode_replacements} undecodable byte(s) were "
            "replaced with U+FFFD; input may not be valid UTF-8 and that content was not "
            "scanned for sensitive data (try --encoding, or verify the source encoding)",
            file=sys.stderr,
        )
    report_path = getattr(args, "report", None)
    if report_path:
        from safestream_redactor.report import build_report, write_report

        write_report(
            report_path,
            build_report(
                stats,
                files=files,
                duration_seconds=time.monotonic() - started,
                version=__version__,
            ),
        )


def _cmd_redact(args: argparse.Namespace) -> int:
    redactor = _build_redactor(args)
    budget_workers = _plan_budget(args, redactor)
    if budget_workers is not None:
        # The budget caps concurrency: never exceed what it permits.
        requested = getattr(args, "workers", None)
        args.workers = budget_workers if requested is None else min(requested, budget_workers)
    if args.input not in ("-", None) and os.path.isdir(args.input):
        return _redact_directory(args, redactor)
    started = time.monotonic()
    encoding = getattr(args, "encoding", "utf-8")
    stats = RedactionStats()
    chunks = _input_chunks(args.input, redactor.chunk_size, encoding)
    if args.output == "-":
        _write_stdout(redactor.redact_stream(chunks, stats), encoding)
    elif args.input == "-":
        _atomic_write_stream(args.output, redactor.redact_stream(chunks, stats), encoding)
    elif getattr(args, "workers", None) and args.workers > 1:
        from safestream_redactor.parallel import redact_file_parallel

        stats = redact_file_parallel(
            redactor,
            args.input,
            args.output,
            workers=args.workers,
            encoding=encoding,
            offline_guard=getattr(args, "offline_guard", True),
            worker_address_space_limit=getattr(args, "_per_worker_bytes", None),
        ).stats
    else:
        stats = redactor.redact_file(args.input, args.output, encoding=encoding)
    _finish_run(args, stats, files=1, started=started)
    return 0


def _redact_directory(args: argparse.Namespace, redactor: Redactor) -> int:
    from safestream_redactor.scheduler import redact_tree

    if args.output in ("-", None):
        raise SystemExit("directory input requires an output directory (-o DIR)")
    started = time.monotonic()

    # live progress only on an interactive stderr; a carriage-return line would
    # just be noise in CI logs or a redirected file
    progress = None
    if sys.stderr.isatty():

        def progress(done: int, total: int) -> None:
            end = "\n" if done == total else "\r"
            print(f"-- redacting: {done}/{total} files", end=end, file=sys.stderr, flush=True)

    results = redact_tree(
        args.input,
        args.output,
        redactor,
        workers=args.workers,
        encoding=getattr(args, "encoding", "utf-8"),
        offline_guard=getattr(args, "offline_guard", True),
        progress=progress,
    )
    stats = RedactionStats()
    for r in results:
        stats.counts.update(r.counts)
        stats.chars_in += r.chars_in
        stats.chars_out += r.chars_out
        stats.decode_replacements += r.decode_replacements
    total = sum(r.bytes_written for r in results)
    print(
        f"-- redacted {len(results)} file(s), {total} bytes written to {args.output}",
        file=sys.stderr,
    )
    _finish_run(args, stats, files=len(results), started=started)
    return 0


# Directories that hold version-control internals, never tracked content: a
# `detect .` in a repo would otherwise scan every packed object in .git/.
_SKIP_DIRS = frozenset({".git", ".hg", ".svn"})
# Bytes sniffed to classify a file found by directory traversal as binary.
_BINARY_SNIFF = 8192


def _is_binary(path: Path) -> bool:
    """A NUL byte in the first block marks a binary file (the heuristic git uses)."""
    try:
        with path.open("rb") as f:
            return b"\0" in f.read(_BINARY_SNIFF)
    except OSError:
        return False  # unreadable: let the scan itself report the error


def _expand_inputs(paths: list[str]) -> Iterator[str]:
    """Expand directory arguments into the files beneath them, in sorted order.

    Files and ``-`` pass through untouched (an explicitly named file is always
    scanned). Traversal mirrors :func:`~safestream_redactor.scheduler.redact_tree`
    — symlinks are skipped so a link cannot pull an out-of-tree file into the
    scan — and additionally skips VCS metadata directories and binary files,
    which hold no reviewable text and only produce decode noise.
    """
    for path in paths:
        if path == "-" or not os.path.isdir(path):
            yield path
            continue
        root = Path(path)
        for p in sorted(root.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            if _SKIP_DIRS.intersection(p.relative_to(root).parts[:-1]):
                continue
            if not _is_binary(p):
                yield str(p)


def _cmd_detect(args: argparse.Namespace) -> int:
    redactor = _build_redactor(args)
    # validate the single-stream footprint; fail closed if it can't fit
    _plan_budget(args, redactor)
    sarif = getattr(args, "sarif", False)
    # Matched text is hidden unless explicitly requested: detect output ends up
    # in CI logs, hook output, and terminals that get screen-shared or recorded.
    show_text = getattr(args, "show_text", False)
    findings = []
    if sarif:
        from safestream_redactor.sarif import Finding

    count = 0
    # `detect` accepts one or more inputs (files, directories, or '-'); each file
    # is scanned independently and its findings carry that file's path. SARIF
    # findings accumulate into one report.
    encoding = getattr(args, "encoding", "utf-8")
    for path in _expand_inputs(args.input):
        offset = 0
        uri = path if path != "-" else "stdin"
        lines = LineTracker()
        for segment, detections in redactor.detect_stream(
            _input_chunks(path, redactor.chunk_size, encoding)
        ):
            for det in detections:
                count += 1
                start, end = offset + det.start, offset + det.end
                line, col = lines.locate(segment, offset, start)
                if sarif:
                    end_line, end_col = lines.locate(segment, offset, end)
                    findings.append(
                        Finding(
                            det.entity_type,
                            start,
                            end,
                            det.confidence,
                            det.source,
                            uri=uri,
                            line=line,
                            column=col,
                            end_line=end_line,
                            end_column=end_col,
                        )
                    )
                elif args.json:
                    record: dict[str, object] = {
                        "file": uri,
                        "type": det.entity_type.value,
                        "start": start,
                        "end": end,
                        "line": line,
                        "column": col,
                    }
                    if show_text:
                        record["text"] = det.text
                    record["confidence"] = round(det.confidence, 3)
                    record["source"] = det.source
                    print(json.dumps(record))
                else:
                    shown = f"  {det.text!r}" if show_text else ""
                    print(
                        f"{uri}:{line}:{col}: {det.entity_type.value}  "
                        f"conf={det.confidence:.2f}{shown}"
                    )
            lines.finish(segment, offset)
            offset += len(segment)
    if sarif:
        from safestream_redactor.sarif import build_sarif

        print(json.dumps(build_sarif(findings, version=__version__), indent=2))
    elif not args.json:
        hint = " (matched text hidden; --show-text reveals it)" if count and not show_text else ""
        print(f"-- {count} detection(s){hint}", file=sys.stderr)
    if args.fail_on_detect and count:
        return 1
    return 0


def _is_loopback(host: str) -> bool:
    import ipaddress

    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a hostname other than localhost: assume reachable


def _cmd_serve(args: argparse.Namespace) -> int:
    from safestream_redactor.api import DEFAULT_MAX_BODY_BYTES, serve

    redactor = _server_redactor(args)
    max_body = args.max_body if args.max_body is not None else DEFAULT_MAX_BODY_BYTES
    if not _is_loopback(args.host):
        print(
            f"safestream: warning: binding {args.host!r} exposes an unauthenticated "
            "redaction API beyond this machine; anyone who can reach the port can submit "
            "text (and read /redact results). Prefer 127.0.0.1 behind an authenticating "
            "proxy.",
            file=sys.stderr,
        )
    print(
        f"-- safestream REST API on http://{args.host}:{args.port} "
        f"(tiers: {', '.join(redactor.detector_names)})",
        file=sys.stderr,
    )
    serve(redactor, host=args.host, port=args.port, max_body_bytes=max_body)
    return 0


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    from safestream_redactor.mcp_server import serve_stdio

    redactor = _server_redactor(args)
    # The MCP server is local stdio only; the offline guard stays on so a
    # misbehaving policy/plugin still cannot reach the network mid-session.
    from safestream_redactor import netguard

    netguard.install()
    serve_stdio(redactor)
    return 0


def _cmd_ui(args: argparse.Namespace) -> int:
    from safestream_redactor.ui.launcher import launch

    if not _is_loopback(args.host):
        print(
            f"safestream: warning: binding {args.host!r} exposes the playground (and "
            "anything pasted into it) beyond this machine; prefer 127.0.0.1",
            file=sys.stderr,
        )
    return launch(args.host, args.port, headless=args.headless)


def _apply_offline_hard(mode: str | None) -> None:
    """Enable an opt-in kernel-enforced offline mode, warning on fallback.

    ``auto`` prefers the network namespace (the most complete boundary) and
    falls back to the seccomp filter. Applied in the main process before any
    worker forks, so children inherit the containment. Never fatal: an
    unsupported platform degrades to the in-process guard with a warning.
    """
    if not mode:
        return
    from safestream_redactor.netguard_hard import (
        enable_network_namespace,
        enable_seccomp_inet_block,
    )

    if mode == "seccomp":
        result = enable_seccomp_inet_block()
    elif mode == "netns":
        result = enable_network_namespace()
    else:  # auto
        result = enable_network_namespace()
        if not result.applied:
            result = enable_seccomp_inet_block()
    if result.applied:
        print(f"-- offline hard mode active [{result.mode}]: {result.reason}", file=sys.stderr)
    else:
        print(
            f"safestream: warning: could not enable hard offline mode ({result.reason}); "
            "continuing with the in-process network guard only",
            file=sys.stderr,
        )


class _StderrWarnings(logging.Handler):
    """Print library warnings to the *current* ``sys.stderr``.

    The package installs a ``NullHandler`` (library etiquette), so without this
    the CLI swallowed every warning the library raises: an unsafe overlap being
    accepted, a span longer than the overlap, a plugin that failed to load or was
    skipped. Those are coverage risks the person running the command must see.
    Resolving ``sys.stderr`` at emit time (rather than binding a stream once)
    keeps it correct when stderr is swapped, e.g. by test capture.
    """

    def emit(self, record: logging.LogRecord) -> None:
        print(f"safestream: {record.levelname.lower()}: {record.getMessage()}", file=sys.stderr)


_STDERR_WARNINGS = _StderrWarnings(logging.WARNING)


def _surface_library_warnings() -> None:
    logger = logging.getLogger("safestream_redactor")
    if _STDERR_WARNINGS not in logger.handlers:
        logger.addHandler(_STDERR_WARNINGS)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _surface_library_warnings()
    if args.command == "init-config":
        return _cmd_init_config(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "mcp-serve":
        return _cmd_mcp_serve(args)
    if args.command == "ui":
        return _cmd_ui(args)
    if getattr(args, "offline_guard", True):
        from safestream_redactor import netguard

        netguard.install()
    _apply_offline_hard(getattr(args, "offline_hard", None))
    from safestream_redactor.memory_budget import ResourceExhaustionError

    try:
        if args.command == "redact":
            return _cmd_redact(args)
        return _cmd_detect(args)
    except ResourceExhaustionError as exc:
        # Fail-closed memory-budget refusal gets its own exit code (3) so CI and
        # scripts can distinguish "would not fit" from an ordinary I/O error.
        print(f"safestream: resource-exhaustion: {exc}", file=sys.stderr)
        return 3
    except MemoryError:
        # The kernel RLIMIT_AS cap (from --memory-limit) refused an allocation:
        # the run exceeded its budget and fails closed with the same exit code as
        # a pre-flight refusal, rather than being killed or silently degrading.
        print(
            "safestream: resource-exhaustion: allocation refused by the enforced "
            "memory limit (RLIMIT_AS); the run exceeded its --memory-limit budget",
            file=sys.stderr,
        )
        return 3
    except (OSError, ValueError) as exc:
        print(f"safestream: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
