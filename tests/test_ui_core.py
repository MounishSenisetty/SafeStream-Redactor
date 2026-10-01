"""Web UI logic (ui/core.py). Framework-free: runs without the [ui] extra."""

from __future__ import annotations

import itertools

import pytest

from safestream_redactor import Redactor
from safestream_redactor.ui.core import (
    MAX_INPUT_BYTES,
    PATTERN_TYPES,
    SAMPLE_TEXT,
    InputError,
    RedactStyle,
    Settings,
    SettingsError,
    build_redactor,
    check_text_size,
    decode_upload,
    download_name,
    finding_rows,
    highlight_html,
    parse_rules,
    privacy_status,
    redact_text,
    scan,
    summarize,
    worst_severity,
)

AWS = "AKIAIOSFODNN7EXAMPLE"


# -- settings -> redactor ---------------------------------------------------


def test_parse_rules_skips_blanks_comments_and_duplicates():
    block = "ProjectX\n\n  # a comment\n  Jane Doe  \nProjectX\r\n"
    assert parse_rules(block) == ("ProjectX", "Jane Doe")
    assert parse_rules("") == ()


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (Settings(custom_patterns=("(unclosed",)), "invalid custom pattern"),
        (Settings(chunk_size=0), "chunk_size must be a positive integer"),
        (Settings(overlap=10), "safe minimum"),
        (Settings(min_confidence=1.5), "min_confidence"),
        (Settings(min_confidence=-0.1), "min_confidence"),
        (Settings(style=RedactStyle.HASH), "needs a secret key"),
        (Settings(types=("not_a_type",)), "unknown entity type"),
    ],
)
def test_invalid_settings_become_friendly_errors(settings, message):
    # the page shows these as alerts; they must never escape as tracebacks
    with pytest.raises(SettingsError, match=message):
        build_redactor(settings)


def test_missing_ner_dependency_is_a_settings_error(monkeypatch):
    import safestream_redactor.detectors.ner as ner

    def _no_spacy(*args, **kwargs):
        raise ImportError("No module named 'spacy'")

    monkeypatch.setattr(ner.NERDetector, "__init__", _no_spacy)
    with pytest.raises(SettingsError, match=r"\[ner\]"):
        build_redactor(Settings(use_ner=True))


def test_type_selection_semantics():
    everything = build_redactor(Settings())
    assert {"entropy", "labeled_identifier", "contextual"} <= set(everything.detector_names)
    # deselecting every pattern type runs none of them (not "all of them")
    nothing = build_redactor(Settings(types=(), use_entropy=True))
    assert scan(nothing, SAMPLE_TEXT) == []
    only_email = build_redactor(Settings(types=("email",)))
    assert {f.entity_type for f in scan(only_email, SAMPLE_TEXT)} == {"email"}


def test_name_tiers_toggle_together():
    names = build_redactor(Settings(use_names=True)).detector_names
    assert {"gazetteer_name", "semantic_ensemble"} <= set(names)


def test_pattern_types_exclude_model_and_custom_types():
    assert "email" in PATTERN_TYPES
    assert not {"person", "org", "loc", "custom"} & set(PATTERN_TYPES)


# -- scanning and redaction ------------------------------------------------


@pytest.mark.parametrize("style", list(RedactStyle))
def test_ui_output_equals_core_redaction(style):
    # the page adds no logic: its output must be exactly Redactor.redact's
    r = build_redactor(Settings(style=style, hash_key="k"))
    assert redact_text(SAMPLE_TEXT, scan(r, SAMPLE_TEXT)) == r.redact(SAMPLE_TEXT)


def test_small_chunks_find_the_same_entities():
    # the chunk-size setting drives the real streaming path; results must not move
    whole = scan(build_redactor(Settings()), SAMPLE_TEXT)
    chunked = scan(build_redactor(Settings(chunk_size=7)), SAMPLE_TEXT)
    assert [(f.start, f.end, f.entity_type) for f in chunked] == [
        (f.start, f.end, f.entity_type) for f in whole
    ]


def test_findings_carry_locations_and_severity():
    text = "first\r\n  mail bob@x.io\nkey " + AWS
    findings = scan(build_redactor(Settings()), text)
    assert [(f.entity_type, f.line, f.column) for f in findings] == [
        ("email", 2, 8),
        ("aws_key", 3, 5),
    ]
    assert findings[1].severity == "critical"
    assert findings[1].text == AWS and findings[1].replacement == "[REDACTED]"


def test_mask_style_never_shows_more_than_half():
    r = build_redactor(Settings(style=RedactStyle.MASK, keep_last=4))
    (finding,) = scan(r, "ssn: 123-45-6789")
    assert finding.replacement == "*******6789"


def test_summaries():
    findings = scan(build_redactor(Settings()), SAMPLE_TEXT + "a@b.io c@d.io\n")
    counts = summarize(findings)
    assert next(iter(counts)) == "email" and counts["email"] == 3
    assert worst_severity(findings) == "critical"
    assert worst_severity([]) is None


# -- rendering -------------------------------------------------------------


def test_highlight_escapes_untrusted_input():
    # uploaded files are untrusted: markup in them must render as text
    text = '<script>alert(1)</script> "x" mail bob@x.io'
    out = highlight_html(text, scan(build_redactor(Settings()), text))
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "&quot;x&quot;" in out
    assert out.count("<mark ") == 1 and ">bob@x.io</mark>" in out


def test_highlight_redacted_view_shows_replacements():
    text = "mail bob@x.io"
    out = highlight_html(text, scan(build_redactor(Settings()), text), redacted=True)
    assert "bob@x.io" not in out and ">[REDACTED]</mark>" in out


def test_highlight_escapes_custom_replacement_markup():
    r = build_redactor(Settings(replacement="<b>gone</b>"))
    out = highlight_html("mail bob@x.io", scan(r, "mail bob@x.io"), redacted=True)
    assert "<b>" not in out and "&lt;b&gt;gone&lt;/b&gt;" in out


def test_highlight_preview_is_truncated():
    text = "x" * 50 + " mail bob@x.io"
    findings = scan(build_redactor(Settings()), text)
    out = highlight_html(text, findings, limit=20)
    assert "<mark" not in out and out.count("x") == 20


def test_rows_hide_matched_values_unless_revealed():
    findings = scan(build_redactor(Settings()), "key " + AWS)
    (hidden,) = finding_rows(findings)
    assert AWS not in str(hidden.values()) and hidden["Match"] == "•" * 12
    assert hidden["Line:Col"] == "1:5" and hidden["Span"] == "4-24"
    (shown,) = finding_rows(findings, reveal=True)
    assert shown["Match"] == AWS


# -- input guards ----------------------------------------------------------


def test_upload_size_limit():
    with pytest.raises(InputError, match="MiB limit"):
        decode_upload(b"a" * (MAX_INPUT_BYTES + 1))
    assert decode_upload(b"a" * MAX_INPUT_BYTES).text == "a" * MAX_INPUT_BYTES


def test_binary_upload_rejected():
    with pytest.raises(InputError, match="binary"):
        decode_upload(b"\x89PNG\r\n\x1a\n\x00\x00")


def test_upload_decoding_reports_undecodable_bytes_and_strips_bom():
    decoded = decode_upload(b"\xef\xbb\xbfok \xff\xfe end \xef\xbf\xbd")
    assert decoded.text.startswith("ok ")  # BOM gone, columns not shifted
    assert decoded.replaced_bytes == 2  # a literal U+FFFD in the file is not counted


def test_pasted_text_limit_counts_utf8_bytes():
    check_text_size("é" * (MAX_INPUT_BYTES // 2))  # exactly at the cap
    with pytest.raises(InputError):
        check_text_size("é" * (MAX_INPUT_BYTES // 2 + 1))


@pytest.mark.parametrize(
    ("uploaded", "expected"),
    [
        (None, "redacted.txt"),
        ("app.log", "app.redacted.log"),
        ("data.tar.csv", "data.tar.redacted.csv"),
        ("README", "README.redacted.txt"),
        ("../../etc/passwd", "passwd.redacted.txt"),
        ("C:\\Users\\me\\report.json", "report.redacted.json"),
        (".env", ".env.redacted.txt"),
    ],
)
def test_download_name(uploaded, expected):
    assert download_name(uploaded) == expected


# -- privacy banner --------------------------------------------------------


def test_privacy_status_requires_every_guarantee():
    assert privacy_status("127.0.0.1", False, True).local_only
    assert privacy_status("localhost", False, True).local_only
    assert privacy_status("::1", False, True).local_only
    # Streamlit's defaults: all interfaces + browser telemetry
    default = privacy_status(None, True, True)
    assert not default.local_only and len(default.issues) == 2
    assert "all interfaces" in default.issues[0]
    assert not privacy_status("0.0.0.0", False, True).local_only
    assert not privacy_status("myhost", False, True).local_only
    unguarded = privacy_status("127.0.0.1", False, False)
    assert unguarded.issues == ("The offline network guard is not active in this process.",)


def test_core_module_does_not_import_streamlit():
    # the base install must work without the [ui] extra
    import subprocess
    import sys

    code = (
        "import sys, safestream_redactor.ui.core, safestream_redactor.ui.launcher; "
        "sys.exit('streamlit' in sys.modules)"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_redactor_is_a_plain_core_redactor():
    assert isinstance(build_redactor(Settings()), Redactor)


# -- large files -----------------------------------------------------------

from safestream_redactor.ui import core  # noqa: E402


def _big_text(lines: int = 3000) -> str:
    return "".join(
        f"line {i} user{i}@corp.example card 4111 1111 1111 1111 key {AWS}\n"
        if i % 3 == 0
        else f"line {i} nothing to see\n"
        for i in range(lines)
    )


def test_spool_upload_copies_in_blocks(tmp_path):
    import io

    data = _big_text().encode()
    dest = tmp_path / "spooled"
    assert core.spool_upload(io.BytesIO(data), str(dest), chunk_size=4096) == len(data)
    assert dest.read_bytes() == data


def test_spool_upload_refuses_binary(tmp_path):
    import io

    with pytest.raises(InputError, match="binary"):
        core.spool_upload(io.BytesIO(b"\x00\x01ELF" + b"x" * 100), str(tmp_path / "x"))


@pytest.mark.parametrize("workers", [1, 3])
def test_redact_large_matches_the_core_redactor(tmp_path, workers):
    text = _big_text()
    src = tmp_path / "in.log"
    src.write_text(text, encoding="utf-8", newline="")
    r = build_redactor(Settings(chunk_size=4096))
    result = core.redact_large(r, str(src), str(tmp_path / "out.log"), workers=workers)
    assert (tmp_path / "out.log").read_bytes().decode("utf-8") == r.redact(text)
    assert result.stats.counts == {"aws_key": 1000, "credit_card": 1000, "email": 1000}
    assert result.input_bytes == src.stat().st_size
    assert result.output_bytes == (tmp_path / "out.log").stat().st_size
    assert result.workers == workers and result.seconds >= 0


def test_read_head_matches_redaction_decoding(tmp_path):
    src = tmp_path / "in.log"
    src.write_bytes(b"a\r\nb \xff c\n" + b"x" * 100)
    head = core.read_head(str(src), n_chars=10)
    assert head == "a\r\nb � c\nx"  # CRLF kept, bad byte replaced, 10 chars


def test_workdirs_are_private_and_cleaned(tmp_path):
    import os
    import stat

    path = core.new_workdir()
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700 or os.name == "nt"
        assert path in core._WORKDIRS
    finally:
        core.discard_workdir(path)
    assert not os.path.exists(path) and path not in core._WORKDIRS
    core.discard_workdir(None)  # no-op


def test_save_destination_never_overwrites(tmp_path):
    first = core.save_destination(str(tmp_path), "app.log")
    assert first == tmp_path / "app.redacted.log"
    first.write_text("x")
    second = core.save_destination(str(tmp_path), "app.log")
    assert second == tmp_path / "app.redacted-1.log"
    second.write_text("x")
    assert core.save_destination(str(tmp_path), "app.log").name == "app.redacted-2.log"
    # a name that already contains ".redacted" keeps its stem intact
    (tmp_path / "x.redacted.redacted.log").write_text("x")
    assert core.save_destination(str(tmp_path), "x.redacted.log").name == (
        "x.redacted.redacted-1.log"
    )
    # untrusted upload names cannot escape the folder
    assert core.save_destination(str(tmp_path), "../../etc/passwd").parent == tmp_path


def test_save_destination_requires_an_existing_folder(tmp_path):
    with pytest.raises(InputError, match="not an existing folder"):
        core.save_destination(str(tmp_path / "missing"), "a.log")


def test_save_output_moves_the_file(tmp_path):
    out = tmp_path / "work" / "output"
    out.parent.mkdir()
    out.write_text("redacted")
    from safestream_redactor.report import RedactionStats

    result = core.LargeResult(RedactionStats(), str(out), 8, 8, 0.1, 1)
    dest = core.save_output(result, tmp_path / "final.redacted.log")
    assert dest.read_text() == "redacted" and not out.exists()


def test_counts_severity_and_estimate():
    assert core.counts_severity({"email": 3, "aws_key": 1}) == "critical"
    assert core.counts_severity({"ipv4": 2}) == "low"
    assert core.counts_severity({"aws_key": 0}) is None
    assert core.counts_severity({}) is None
    assert core.estimate_seconds(2_400_000, 2) == pytest.approx(1.0)
    assert core.default_workers() >= 1


# -- chunk inspector telemetry ---------------------------------------------------


def _tiny_redactor(**kw) -> Redactor:
    # an overlap far below the safe minimum makes boundaries easy to hit on purpose
    options = {"types": ["email"], **kw}
    return Redactor(
        overlap=64, chunk_size=64, allow_unsafe_overlap=True, use_entropy=False, **options
    )


def test_trace_tiles_the_input_and_matches_redaction():
    text = SAMPLE_TEXT * 200
    r = build_redactor(Settings(chunk_size=8192))
    chunks = list(core.trace_chunks(r, text))
    assert [c.index for c in chunks] == list(range(len(chunks)))
    assert chunks[0].emit_start == 0 and chunks[-1].emit_end == len(text)
    assert all(a.emit_end == b.emit_start for a, b in itertools.pairwise(chunks))
    assert redact_text(text, core.flatten_findings(chunks)) == r.redact(text)
    assert chunks[-1].final and not any(c.final for c in chunks[:-1])
    # steady-state geometry: 8,192 context | 8,192 emitted | 8,192 carried
    mid = chunks[1]
    assert (mid.window_start, mid.emit_start, mid.emit_end, mid.window_end) == (
        0,
        8192,
        16384,
        24576,
    )
    assert mid.carried == 8192
    lines = text[: mid.emit_start].count("\n") + 1
    assert mid.line_start == lines


def test_trace_reports_a_retreat_and_the_entity_it_kept_whole():
    text = "w " * 29 + "bob@corp.io" + " y" * 100
    chunks = list(core.trace_chunks(_tiny_redactor(), text))
    first, second = chunks[0], chunks[1]
    assert first.retreated_by == 6 and first.emit_end == 58 and first.planned_end == 64
    assert first.straddlers == ()
    assert second.straddlers == (0,)
    held = second.findings[0]
    assert (held.start, held.end, held.text) == (58, 69, "bob@corp.io")


def test_trace_reports_deferred_passes():
    r = _tiny_redactor(custom_patterns=[r"Z{100}"], types=[])
    chunks = list(core.trace_chunks(r, "Z" * 100 + " tail" * 40))
    assert chunks[0].deferred_passes == 1  # the first pass was pinned by the match
    assert chunks[0].straddlers == (0,) and chunks[0].findings[0].end == 100


def test_window_findings_matches_a_linear_scan():
    text = SAMPLE_TEXT * 60
    chunks = list(core.trace_chunks(build_redactor(Settings(chunk_size=8192)), text))
    flat = core.flatten_findings(chunks)
    for start, end in [(0, 100), (500, 9000), (8192, 24576), (len(text) - 50, len(text))]:
        naive = [f for f in flat if f.end > start and f.start < end]
        assert core.window_findings(flat, start, end) == naive


def test_window_html_shows_bands_and_the_planned_cut():
    text = "w " * 29 + "bob@corp.io" + " <b>y</b>" * 30
    chunks = list(core.trace_chunks(_tiny_redactor(), text))
    flat = core.flatten_findings(chunks)
    first = chunks[0]
    out = core.window_html(text, first, core.window_findings(flat, 0, first.window_end))
    assert 'class="ss-band ss-emit"' in out and 'class="ss-band ss-carry"' in out
    assert 'class="ss-cut"' in out and 'class="ss-planned"' in out
    assert 'class="ss-band ss-prefix"' not in out  # nothing emitted before pass 1
    # the planned cut splits the held email into two marks around the marker
    assert ">bob@co</mark>" in out and ">rp.io</mark>" in out
    second = chunks[1]
    out2 = core.window_html(text, second, core.window_findings(flat, 0, second.window_end))
    assert 'class="ss-band ss-prefix"' in out2 and 'class="ss-planned"' not in out2
    assert "<b>" not in out2 and "&lt;b&gt;" in out2  # untrusted text is escaped


def test_segment_html_rebases_findings():
    text = "w " * 29 + "bob@corp.io" + " y" * 100
    second = list(core.trace_chunks(_tiny_redactor(), text))[1]
    assert core.segment_html(text, second, redacted=True).startswith('<pre class="ss-view"><mark')
    assert ">[REDACTED]</mark>" in core.segment_html(text, second, redacted=True)
    assert ">bob@corp.io</mark>" in core.segment_html(text, second, redacted=False)


def test_trace_rows_hold_offsets_not_text():
    text = "w " * 29 + "bob@corp.io" + " y" * 100
    rows = core.trace_rows(core.trace_chunks(_tiny_redactor(), text))
    assert rows[0]["Retreat"] == 6 and rows[1]["Held whole"] == 1
    assert rows[0]["Emitted"] == "0-58" and rows[1]["Findings"] == 1
    assert "bob@corp.io" not in str(rows)


def test_inspector_numbers():
    r = build_redactor(Settings())
    assert core.inspector_chunk_sizes(r) == (8192, 16384)
    assert core.inspector_chunk_sizes(build_redactor(Settings(overlap=12000))) == (12000, 24000)
    assert (core.PACING_MIN_MS, core.PACING_DEFAULT_MS, core.PACING_MAX_MS) == (50, 500, 2000)
    assert core.INSPECTOR_RETAINED == 5


def test_pass_html_is_one_escaped_block_with_notices():
    text = "w " * 29 + "bob@corp.io" + " <script>x</script>" * 20
    chunks = list(core.trace_chunks(_tiny_redactor(), text))
    flat = core.flatten_findings(chunks)
    first = core.pass_html(text, chunks, flat, 0)
    assert first.startswith('<div class="ss-pass">') and first.endswith("</div>")
    assert "moved back 6 chars" in first and "emitted whole here" not in first
    second = core.pass_html(text, chunks, flat, 1)
    assert "emitted whole here: email" in second
    assert "<script>" not in second and "&lt;script&gt;" in second
    last = core.pass_html(text, chunks, flat, len(chunks) - 1, retained=3)
    assert last.count('class="ss-seg-title"') == min(3, len(chunks))
