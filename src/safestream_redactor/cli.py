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
import os
import sys
import time
from collections.abc import Iterator

from safestream_redactor import __version__
from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
from safestream_redactor.entities import EntityType
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
        "--no-entropy",
        dest="entropy",
        action="store_false",
        default=True,
        help="disable the high-entropy secret detector (on by default)",
    )
    common.add_argument("--chunk-size", type=int, default=None, metavar="BYTES")
    common.add_argument("--overlap", type=int, default=None, metavar="CHARS")
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
        help="one or more input file paths, or '-' for stdin (accepts many files "
        "so it works as a pre-commit/CI secret gate)",
    )
    detect.add_argument("--json", action="store_true", help="one JSON object per detection")
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
use_entropy = true                          # high-entropy secret detection

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
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(_STARTER_CONFIG)
    print(f"-- wrote starter policy to {args.output}", file=sys.stderr)
    return 0


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
            use_entropy=args.entropy,
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
    if not args.entropy:
        redactor._detectors = [d for d in redactor._detectors if d.name != "entropy"]
    if args.custom_word or args.custom_regex:
        from safestream_redactor.detectors.custom import CustomDetector

        redactor._detectors.insert(1, CustomDetector(args.custom_word, args.custom_regex))
    if args.chunk_size:
        redactor.chunk_size = args.chunk_size
    if args.overlap is not None:
        redactor.overlap = args.overlap
    return redactor


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

    budget = MemoryBudget(limit, model_budget="512MB" if getattr(args, "ner", False) else 0)
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
    """Write streamed output to a temp file, then move it into place atomically.

    Matches :meth:`Redactor.redact_file` durability for the stdin->file path: a
    crash mid-stream can't leave a truncated file that looks fully redacted.
    """
    import contextlib
    import tempfile

    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(path) or ".", prefix=os.path.basename(path) + "."
    )
    try:
        with open(fd, "w", encoding=encoding) as out:
            for piece in pieces:
                out.write(piece)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _input_chunks(path: str, chunk_size: int, encoding: str = "utf-8") -> Iterator[str]:
    if path == "-":
        while chunk := sys.stdin.read(chunk_size):
            yield chunk
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
        for piece in redactor.redact_stream(chunks, stats):
            sys.stdout.write(piece)
        sys.stdout.flush()
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


def _cmd_detect(args: argparse.Namespace) -> int:
    redactor = _build_redactor(args)
    _plan_budget(
        args, redactor
    )  # validate the single-stream footprint; fail closed if it can't fit
    sarif = getattr(args, "sarif", False)
    findings = []
    if sarif:
        from safestream_redactor.sarif import Finding

    count = 0
    # `detect` accepts one or more inputs; each is scanned independently and its
    # findings carry that file's URI. SARIF findings accumulate into one report.
    inputs = args.input if isinstance(args.input, list) else [args.input]
    encoding = getattr(args, "encoding", "utf-8")
    for path in inputs:
        offset = 0
        uri = path if path != "-" else "stdin"
        for segment, detections in redactor.detect_stream(
            _input_chunks(path, redactor.chunk_size, encoding)
        ):
            for det in detections:
                count += 1
                if sarif:
                    findings.append(
                        Finding(
                            det.entity_type,
                            offset + det.start,
                            offset + det.end,
                            det.confidence,
                            det.source,
                            uri=uri,
                        )
                    )
                elif args.json:
                    print(
                        json.dumps(
                            {
                                "file": uri,
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
                    prefix = f"{uri}: " if len(inputs) > 1 else ""
                    print(
                        f"{prefix}{det.entity_type.value:>13}  "
                        f"conf={det.confidence:.2f}  {det.text!r}"
                    )
            offset += len(segment)
    if sarif:
        from safestream_redactor.sarif import build_sarif

        print(json.dumps(build_sarif(findings, version=__version__), indent=2))
    elif not args.json:
        print(f"-- {count} detection(s)", file=sys.stderr)
    if args.fail_on_detect and count:
        return 1
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from safestream_redactor.api import DEFAULT_MAX_BODY_BYTES, serve

    if args.config:
        from safestream_redactor.config import redactor_from_config

        redactor = redactor_from_config(args.config)
    else:
        redactor = Redactor()
    max_body = args.max_body if args.max_body is not None else DEFAULT_MAX_BODY_BYTES
    print(
        f"-- safestream REST API on http://{args.host}:{args.port} "
        f"(tiers: {', '.join(redactor.detector_names)})",
        file=sys.stderr,
    )
    serve(redactor, host=args.host, port=args.port, max_body_bytes=max_body)
    return 0


def _cmd_mcp_serve(args: argparse.Namespace) -> int:
    from safestream_redactor.mcp_server import serve_stdio

    if args.config:
        from safestream_redactor.config import redactor_from_config

        redactor = redactor_from_config(args.config)
    else:
        redactor = Redactor()
    # The MCP server is local stdio only; the offline guard stays on so a
    # misbehaving policy/plugin still cannot reach the network mid-session.
    from safestream_redactor import netguard

    netguard.install()
    serve_stdio(redactor)
    return 0


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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "init-config":
        return _cmd_init_config(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "mcp-serve":
        return _cmd_mcp_serve(args)
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
