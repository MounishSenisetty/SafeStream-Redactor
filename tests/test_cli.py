"""CLI tests, calling main() in-process for speed."""

import json

import pytest

from safestream_redactor.cli import main

SAMPLE = "email bob@x.io ssn: 123-45-6789 codename ProjectX\n"


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "in.txt"
    p.write_bytes(SAMPLE.encode())  # exact bytes: line endings pass through verbatim
    return p


def run(capsys, *argv) -> str:
    assert main([str(a) for a in argv]) == 0
    return capsys.readouterr().out


def test_redact_to_file(sample, tmp_path):
    out = tmp_path / "out.txt"
    assert main(["redact", str(sample), "-o", str(out)]) == 0
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_redact_stdout_with_replace(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--replace", "***")
    assert out == "email *** ssn: *** codename ProjectX\n"


def test_types_filter(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--types", "email")
    assert out == "email [REDACTED] ssn: 123-45-6789 codename ProjectX\n"


def test_custom_word(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--custom-word", "ProjectX")
    assert "ProjectX" not in out


def test_mask_mode(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--mode", "mask", "--keep-last", "4")
    assert "*******6789" in out


def test_pseudonymize_requires_key(sample, tmp_path):
    with pytest.raises(SystemExit):
        main(["redact", str(sample), "-o", str(tmp_path / "o"), "--mode", "pseudonymize"])


def test_per_type_replacement(sample, capsys):
    out = run(capsys, "redact", sample, "-o", "-", "--replace-type", "email=<EMAIL>")
    assert "<EMAIL>" in out and "ssn: [REDACTED]" in out


def test_detect_json(sample, capsys):
    out = run(capsys, "detect", sample, "--json")
    records = [json.loads(line) for line in out.splitlines()]
    assert {r["type"] for r in records} == {"email", "ssn"}
    assert all({"start", "end", "line", "column", "confidence"} <= r.keys() for r in records)
    assert all("text" not in r for r in records)  # hidden by default


@pytest.mark.parametrize("flag", ["--show-text", "--reveal-matches"])
def test_detect_json_reveals_text_only_on_request(sample, capsys, flag):
    out = run(capsys, "detect", sample, "--json", flag)
    assert {json.loads(line)["text"] for line in out.splitlines()} == {"bob@x.io", "123-45-6789"}


def test_fail_on_detect_gates_ci(sample, tmp_path, capsys):
    # findings -> exit 1; clean input -> exit 0
    assert main(["detect", str(sample), "--fail-on-detect"]) == 1
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing sensitive here\n")
    assert main(["detect", str(clean), "--fail-on-detect"]) == 0
    capsys.readouterr()


def test_stdin_stdout(capsys, monkeypatch):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ip 10.0.0.1 here"))
    out = run(capsys, "redact", "-", "-o", "-")
    assert out == "ip [REDACTED] here"


def test_stdin_to_file(capsys, monkeypatch, tmp_path):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ip 10.0.0.1 here"))
    out = tmp_path / "out.txt"
    assert main(["redact", "-", "-o", str(out)]) == 0
    assert out.read_text() == "ip [REDACTED] here"


def test_missing_input_file_errors(capsys, tmp_path):
    assert main(["redact", str(tmp_path / "nope.txt"), "-o", "-"]) == 1
    assert "error" in capsys.readouterr().err


@pytest.fixture
def no_kernel_limit(monkeypatch):
    """Keep --memory-limit from capping the pytest process itself.

    The real RLIMIT_AS is irreversible for a non-root process, so in-process
    CLI tests exercise admission control only; tests/test_memory_enforcement.py
    covers the kernel cap inside forked children.
    """
    import safestream_redactor.memory_budget as mb

    monkeypatch.setattr(
        mb,
        "enforce_address_space_limit",
        lambda _growth: mb.AddressSpaceLimit(False, "none", None, "stubbed in tests"),
    )


def test_memory_limit_generous_admits(sample, tmp_path, capsys, no_kernel_limit):
    out = tmp_path / "out.txt"
    assert main(["redact", str(sample), "-o", str(out), "--memory-limit", "256MB"]) == 0
    assert "memory budget" in capsys.readouterr().err
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_memory_limit_fail_closed_exit_3(sample, capsys):
    # A 1 MB budget cannot hold even one worker's working set: fail closed.
    assert main(["detect", str(sample), "--memory-limit", "1MB"]) == 3
    assert "resource-exhaustion" in capsys.readouterr().err


def test_memory_limit_caps_workers(sample, tmp_path, capsys, no_kernel_limit):
    out = tmp_path / "out.txt"
    # Ask for many workers under a tight budget; the run still succeeds because
    # the budget silently caps concurrency rather than exceeding the limit.
    assert (
        main(["redact", str(sample), "-o", str(out), "--memory-limit", "48MB", "--workers", "16"])
        == 0
    )
    assert out.read_text() == "email [REDACTED] ssn: [REDACTED] codename ProjectX\n"


def test_memory_limit_bad_value_errors(sample, capsys):
    assert main(["detect", str(sample), "--memory-limit", "notasize"]) == 1
    assert "error" in capsys.readouterr().err


def test_no_entropy_flag_disables_both_entropy_tiers_with_config(tmp_path):
    # Regression (F3): via the --config overlay path, --no-entropy must remove
    # BOTH the base entropy tier and the compound-secret tier, matching the
    # constructor's use_entropy gating.
    from safestream_redactor.cli import _build_parser, _build_redactor

    cfg = tmp_path / "policy.toml"
    cfg.write_text("[detection]\nuse_entropy = true\n", encoding="utf-8")
    args = _build_parser().parse_args(
        ["redact", "in.txt", "-o", "out.txt", "--config", str(cfg), "--no-entropy"]
    )
    redactor = _build_redactor(args)
    assert "entropy" not in redactor.detector_names
    assert "compound_secret" not in redactor.detector_names


def test_constructor_use_entropy_false_disables_both_tiers():
    from safestream_redactor.redactor import Redactor

    names = Redactor(use_entropy=False).detector_names
    assert "entropy" not in names
    assert "compound_secret" not in names
    # sanity: they are present when entropy is enabled (the default)
    on = Redactor(use_entropy=True).detector_names
    assert "entropy" in on and "compound_secret" in on


# --------------------------------------------------------------------------
# detect: log-safe output, file:line:col locations, directory inputs
# --------------------------------------------------------------------------

AWS = "AKIAIOSFODNN7EXAMPLE"


def test_detect_hides_matched_text_by_default(tmp_path, capsys):
    # detect output lands in CI logs and hook output; it used to print the
    # secret verbatim, including from the bundled pre-commit hook and Action
    src = tmp_path / "leak.env"
    src.write_text(f"key = {AWS}\nmail bob@x.io\n")
    for extra in ([], ["--json"]):
        assert main(["detect", str(src), "--fail-on-detect", *extra]) == 1
        captured = capsys.readouterr()
        assert AWS not in captured.out + captured.err
        assert "bob@x.io" not in captured.out + captured.err
        assert "aws_key" in captured.out
    main(["detect", str(src)])
    assert "--show-text reveals it" in capsys.readouterr().err


def test_show_text_reveals_matches_for_local_triage(tmp_path, capsys):
    src = tmp_path / "leak.env"
    src.write_text(f"key = {AWS}\n")
    out = run(capsys, "detect", src, "--show-text")
    assert f"{src}:1:7: aws_key  conf=" in out and repr(AWS) in out


def test_detect_reports_line_and_column(tmp_path, capsys):
    src = tmp_path / "f.txt"
    src.write_bytes(b"first line\r\n  mail bob@x.io\nkey " + AWS.encode() + b"\n")
    out = run(capsys, "detect", src)
    assert f"{src}:2:8: email" in out
    assert f"{src}:3:5: aws_key" in out
    records = [json.loads(line) for line in run(capsys, "detect", src, "--json").splitlines()]
    assert [(r["line"], r["column"]) for r in records] == [(2, 8), (3, 5)]


def test_line_numbers_survive_chunk_boundaries(tmp_path, capsys):
    # a small window (still wider than every entity here) splits the input into
    # ~20 segments; positions carried across them must still be exact
    lines = [f"filler line {i}" for i in range(40)]
    lines[5] = "  contact bob@x.io"
    lines[33] = "mail al@y.io"
    src = tmp_path / "f.txt"
    src.write_text("\n".join(lines) + "\n")
    argv = ["detect", src, "--chunk-size", "16", "--overlap", "32", "--allow-unsafe-overlap"]
    out = run(capsys, *argv)
    assert f"{src}:6:11: email" in out
    assert f"{src}:34:6: email" in out


def test_detect_walks_directories(tmp_path, capsys):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "cfg.env").write_text(f"key = {AWS}\n")
    (root / "clean.txt").write_text("nothing here\n")
    # VCS internals and binary files are skipped when found by traversal
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("mail bob@x.io\n")
    (root / "blob.bin").write_bytes(b"\x00\x01 mail bob@x.io")
    assert main(["detect", str(root), "--json", "--fail-on-detect"]) == 1
    files = {json.loads(line)["file"] for line in capsys.readouterr().out.splitlines()}
    assert files == {str(root / "src" / "cfg.env")}


def test_explicitly_named_binary_file_is_still_scanned(tmp_path, capsys):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x00\x01 mail bob@x.io")
    assert main(["detect", str(blob), "--fail-on-detect"]) == 1
    capsys.readouterr()


@pytest.mark.skipif(not hasattr(__import__("os"), "symlink"), reason="needs symlinks")
def test_detect_directory_walk_skips_symlinks(tmp_path, capsys):
    outside = tmp_path / "outside.txt"
    outside.write_text("mail bob@x.io\n")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not permitted here")
    assert main(["detect", str(root), "--fail-on-detect"]) == 0
    capsys.readouterr()


def test_zero_chunk_size_flag_is_an_error_not_an_empty_output(sample, tmp_path, capsys):
    out = tmp_path / "out.txt"
    assert main(["redact", str(sample), "-o", str(out), "--chunk-size", "0"]) == 1
    assert "chunk_size must be a positive integer" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize(
    ("host", "loopback"),
    [("127.0.0.1", True), ("::1", True), ("localhost", True), ("0.0.0.0", False)],
)
def test_serve_warns_when_not_loopback(monkeypatch, capsys, host, loopback):
    monkeypatch.setattr("safestream_redactor.api.serve", lambda *a, **k: None)
    assert main(["serve", "--host", host, "--port", "0"]) == 0
    assert ("unauthenticated" in capsys.readouterr().err) is not loopback


def test_flags_merge_over_config_into_one_construction(tmp_path, monkeypatch):
    # The optional tiers need spaCy/onnxruntime, so capture the constructor
    # arguments instead: this is the contract (config first, flags on top).
    from safestream_redactor import cli

    captured = {}

    class _Spy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    cfg = tmp_path / "p.toml"
    cfg.write_text('[custom]\npatterns = ["cfg-\\\\d+"]\n[detection]\nuse_ner = false\n')
    monkeypatch.setattr(cli, "Redactor", _Spy)
    args = cli._build_parser().parse_args(
        [
            "redact", "in", "-o", "-", "--config", str(cfg),
            "--custom-regex", "cli-\\d+", "--ner",
            "--onnx", "m.onnx", "--onnx-vocab", "v.json", "--onnx-min-score", "0.7",
        ]
    )  # fmt: skip
    cli._build_redactor(args)
    assert captured["custom_patterns"] == ["cfg-\\d+", "cli-\\d+"]
    assert captured["use_ner"] is True
    assert captured["use_onnx"] is True
    assert (captured["onnx_model"], captured["onnx_vocab"]) == ("m.onnx", "v.json")
    assert captured["onnx_min_score"] == 0.7


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--replace-type", "email"], "TYPE=TEXT"),
        (["--onnx", "m.onnx"], "--onnx-vocab"),
    ],
)
def test_malformed_flags_exit_with_a_message(sample, argv, message):
    with pytest.raises(SystemExit, match=message):
        main(["redact", str(sample), "-o", "-", *argv])


def test_backend_flag_overrides_config(tmp_path, monkeypatch):
    """--backend reaches the Redactor and, like every scalar flag, beats the config."""
    from safestream_redactor import cli

    seen: list[str | None] = []
    real = cli.Redactor

    def spy(*args, **kwargs):
        seen.append(kwargs.get("backend"))
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "Redactor", spy)
    cfg = tmp_path / "policy.toml"
    cfg.write_text('[detection]\nbackend = "python"\n', encoding="utf-8")
    base = ["redact", "in.txt", "-o", "out.txt", "--config", str(cfg)]
    cli._build_redactor(cli._build_parser().parse_args([*base, "--backend", "auto"]))
    cli._build_redactor(cli._build_parser().parse_args(base))
    assert seen == ["auto", "python"]


def test_backend_flag_end_to_end(sample, capsys):
    # "auto" uses the native core when installed and Python otherwise; the output
    # is byte-identical either way
    assert run(capsys, "redact", sample, "-o", "-", "--backend", "auto") == run(
        capsys, "redact", sample, "-o", "-"
    )


def test_backend_flag_rejects_unknown_engine(sample):
    with pytest.raises(SystemExit) as exc:
        main(["redact", str(sample), "-o", "-", "--backend", "gpu"])
    assert exc.value.code == 2
