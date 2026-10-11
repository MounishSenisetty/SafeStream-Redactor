"""The Streamlit page, driven headlessly. Needs the [ui] extra; skipped otherwise."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from streamlit import config as st_config
from streamlit.testing.v1 import AppTest

from safestream_redactor import netguard
from safestream_redactor.ui.core import SAMPLE_TEXT, RedactStyle
from safestream_redactor.ui.launcher import APP_PATH

AWS = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def app() -> Iterator[AppTest]:
    # The page installs the offline guard in its own process; under AppTest that
    # process is pytest's, so put it back the way we found it.
    guarded = netguard.is_installed()
    at = AppTest.from_file(str(APP_PATH), default_timeout=60)
    try:
        yield at.run()
    finally:
        if not guarded:
            netguard.uninstall()


def _no_errors(at: AppTest) -> None:
    assert not at.exception, [e.value for e in at.exception]


def test_empty_page_prompts_for_input(app: AppTest) -> None:
    _no_errors(app)
    assert "Paste text or upload a file" in app.info[0].value
    assert app.radio(key="mode").value == "Detect"


def test_banner_is_honest_under_streamlit_defaults(app: AppTest) -> None:
    # plain `streamlit run`: all interfaces + browser telemetry -> no local claim
    assert not app.success
    assert "not fully local" in app.warning[0].value


def test_banner_confirms_local_only_under_launcher_settings() -> None:
    saved = {k: st_config.get_option(k) for k in ("server.address", "browser.gatherUsageStats")}
    st_config.set_option("server.address", "127.0.0.1")
    st_config.set_option("browser.gatherUsageStats", False)
    guarded = netguard.is_installed()
    try:
        at = AppTest.from_file(str(APP_PATH), default_timeout=60).run()
        assert "Local-only processing" in at.success[0].value
        assert netguard.is_installed()  # the page armed the guard
    finally:
        for key, value in saved.items():
            st_config.set_option(key, value)
        if not guarded:
            netguard.uninstall()


def test_detect_mode_lists_findings_without_revealing_them(app: AppTest) -> None:
    app.button[0].click().run()  # "Load sample log"
    _no_errors(app)
    assert app.text_area(key="text").value == SAMPLE_TEXT
    metrics = {m.label: m.value for m in app.metric}
    # 9: the db URL's userinfo user ("app") is a username field since Phase 1
    assert metrics["Findings"] == "9" and metrics["Highest severity"] == "critical"
    table = app.dataframe[0].value
    # the phone finding starts at its "+1" (col 82): the country code is redacted too
    assert list(table["Line:Col"])[:2] == ["1:46", "1:82"]
    assert AWS not in table.to_string()  # hidden by default
    app.toggle(key="reveal").set_value(True).run()
    assert AWS in app.dataframe[0].value.to_string()


def test_redact_mode_outputs_sanitized_text_and_download(app: AppTest) -> None:
    app.text_area(key="text").set_value(f"mail bob@corp.example key {AWS}").run()
    app.radio(key="mode").set_value("Redact").run()
    _no_errors(app)
    assert app.code[0].value == "mail [REDACTED] key [REDACTED]"
    app.text_area(key="text").set_value("ssn: 123-45-6789").run()
    for style, expected in ((RedactStyle.MASK, "*******6789"), (RedactStyle.HASH, "<SSN_")):
        app.radio(key="style").set_value(style).run()
        _no_errors(app)
        assert expected in app.code[0].value
        assert "123-45-6789" not in app.code[0].value


def test_invalid_regex_is_a_friendly_error(app: AppTest) -> None:
    app.text_area(key="text").set_value("hello").run()
    app.text_area(key="custom_patterns").set_value("(unclosed").run()
    _no_errors(app)
    assert "invalid custom pattern" in app.error[0].value


def test_unsafe_overlap_is_a_friendly_error(app: AppTest) -> None:
    app.text_area(key="text").set_value("hello").run()
    app.number_input(key="overlap").set_value(16).run()
    _no_errors(app)
    assert "safe minimum" in app.error[0].value


def test_custom_words_are_redacted(app: AppTest) -> None:
    app.text_area(key="text").set_value("codename ProjectX ships").run()
    app.text_area(key="custom_words").set_value("ProjectX\n# comment\n").run()
    app.radio(key="mode").set_value("Redact").run()
    assert app.code[0].value == "codename [REDACTED] ships"


def test_oversized_paste_is_refused(app: AppTest, monkeypatch: pytest.MonkeyPatch) -> None:
    import safestream_redactor.ui.core as core

    monkeypatch.setattr(core, "MAX_INPUT_BYTES", 10)
    app.text_area(key="text").set_value("x" * 11).run()
    _no_errors(app)
    assert "limit" in app.error[0].value
    assert not app.metric  # nothing was scanned


# -- large uploads (AppTest cannot upload, so the uploader returns a fake) ----


class _FakeUpload:
    """Quacks like Streamlit's UploadedFile: a BytesIO with a name, size, and id."""

    def __init__(self, data: bytes, name: str = "big.log") -> None:
        import io

        self._buf = io.BytesIO(data)
        self.name, self.size, self.file_id = name, len(data), f"id-{len(data)}"

    def seek(self, pos: int) -> int:
        return self._buf.seek(pos)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def getvalue(self) -> bytes:  # the large-file path must never call this
        raise AssertionError("large uploads must be streamed, not copied whole")


@pytest.fixture
def large_upload(monkeypatch: pytest.MonkeyPatch, tmp_path) -> _FakeUpload:
    import streamlit as st

    import safestream_redactor.ui.core as core

    monkeypatch.setattr(core, "MAX_INPUT_BYTES", 1024)  # anything over 1 KiB is "large"
    line = f"user bob@corp.example key {AWS} card 4111 1111 1111 1111\nok\n"
    upload = _FakeUpload((line * 200).encode())
    monkeypatch.setattr(st, "file_uploader", lambda *a, **k: upload)
    monkeypatch.setenv("SAFESTREAM_UI_OUTPUT_DIR", str(tmp_path))
    return upload


def _local_config() -> dict[str, object]:
    saved = {k: st_config.get_option(k) for k in ("server.address", "browser.gatherUsageStats")}
    st_config.set_option("server.address", "127.0.0.1")
    st_config.set_option("browser.gatherUsageStats", False)
    return saved


def test_large_upload_is_processed_on_request_and_saved(app, large_upload, tmp_path) -> None:
    saved_config = _local_config()
    try:
        app.run()
        _no_errors(app)
        assert "streaming engine" in app.info[0].value
        # nothing runs until asked: a big job must not start on an incidental rerun
        assert not app.metric
        app.button(key="process_large").click().run()
        _no_errors(app)
        metrics = {m.label: m.value for m in app.metric}
        assert metrics["Findings"] == "600" and metrics["Highest severity"] == "critical"
        state = app.session_state["large"]
        workdir = state["workdir"]
        assert not (Path(workdir) / "input").exists()  # the spooled copy is gone

        app.radio(key="mode").set_value("Redact").run()
        _no_errors(app)
        assert app.text_input(key="save_dir").value == str(tmp_path)
        app.button(key="save_large").click().run()
        _no_errors(app)
        (saved,) = tmp_path.glob("big.redacted*.log")
        text = saved.read_text()
        assert AWS not in text and "bob@corp.example" not in text
        assert text.count("[REDACTED]") == 600
        assert "Saved to" in app.success[-1].value
        assert not Path(workdir).exists()  # scratch folder removed once saved
    finally:
        for key, value in saved_config.items():
            st_config.set_option(key, value)


def test_large_upload_settings_change_needs_reprocessing(app, large_upload) -> None:
    app.run()
    app.button(key="process_large").click().run()
    assert app.metric
    app.slider(key="min_confidence").set_value(0.9).run()
    _no_errors(app)
    assert not app.metric  # stale results are never shown for new settings
    app.button(key="process_large").click().run()
    assert {m.label: m.value for m in app.metric}["Findings"] != "600"


def test_large_output_is_not_saved_to_disk_when_not_local(app, large_upload) -> None:
    app.run()
    app.button(key="process_large").click().run()
    app.radio(key="mode").set_value("Redact").run()
    _no_errors(app)
    # Streamlit defaults (all interfaces): a remote visitor must not write files here
    assert not [t for t in app.text_input if t.key == "save_dir"]
    assert any("only when the page is served on loopback" in c.value for c in app.caption)


# -- Inspect mode -------------------------------------------------------------


def _inspect(app: AppTest, text: str) -> AppTest:
    app.text_area(key="text").set_value(text).run()
    app.radio(key="mode").set_value("Inspect").run()
    _no_errors(app)
    return app


def _pass_block(app: AppTest) -> str:
    return next(h.proto.body for h in app.get("html") if 'class="ss-pass"' in h.proto.body)


def _pass_header(app: AppTest) -> str:
    import re

    return re.sub(r"<[^>]+>", "", _pass_block(app).split("</p>", 1)[0])


def test_inspect_steps_through_the_engine_passes(app: AppTest) -> None:
    from safestream_redactor.ui.core import (
        INSPECTOR_RETAINED,
        Settings,
        build_redactor,
        trace_chunks,
    )

    text = SAMPLE_TEXT * 400  # ~187k chars: 23 passes at the 8,192 floor
    _inspect(app, text)
    expected = list(trace_chunks(build_redactor(Settings(chunk_size=8192)), text))
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Passes"] == str(len(expected))
    assert metrics["Boundary retreats"] == str(sum(1 for c in expected if c.retreated_by))
    assert _pass_header(app).startswith(f"Pass 1 of {len(expected)}")

    app.button(key="inspect_step").click().run()
    assert _pass_header(app).startswith("Pass 2 of")
    assert "scanned 0-24,576" in _pass_header(app)  # 8,192 context + emit + carry
    app.button(key="inspect_back").click().run()
    assert _pass_header(app).startswith("Pass 1 of")
    app.button(key="inspect_back").click().run()  # clamped at the first pass
    assert _pass_header(app).startswith("Pass 1 of")

    app.slider(key="inspect_index").set_value(len(expected) - 1).run()
    _no_errors(app)
    assert _pass_header(app).startswith(f"Pass {len(expected)} of")
    # the retained history is capped; the archive table holds every replayed pass
    assert _pass_block(app).count('class="ss-seg-title"') == INSPECTOR_RETAINED
    assert len(app.dataframe[0].value) == len(expected)


def test_inspect_explains_boundary_retreats(app: AppTest) -> None:
    from safestream_redactor.ui.core import Settings, build_redactor, trace_chunks

    text = SAMPLE_TEXT * 400
    chunks = list(trace_chunks(build_redactor(Settings(chunk_size=8192)), text))
    retreat = next(c for c in chunks if c.retreated_by)
    _inspect(app, text)
    app.slider(key="inspect_index").set_value(retreat.index).run()
    block = _pass_block(app)
    assert "moved back" in block
    assert 'class="ss-planned"' in block and 'class="ss-cut"' in block
    app.button(key="inspect_step").click().run()
    assert "emitted whole here" in _pass_block(app)


def test_inspect_play_and_pause(app: AppTest) -> None:
    _inspect(app, SAMPLE_TEXT * 400)
    play = next(b for b in app.button if b.label == "Play")
    play.click().run()
    assert app.session_state["inspect_playing"] is True
    assert _pass_header(app).startswith("Pass 2 of")  # first step taken at once
    next(b for b in app.button if b.label == "Pause").click().run()
    assert app.session_state["inspect_playing"] is False
    assert any(b.label == "Play" for b in app.button)


def test_inspect_pacing_and_chunk_choices_come_from_the_approved_numbers(app: AppTest) -> None:
    from safestream_redactor.ui.core import Settings, build_redactor, trace_chunks

    text = SAMPLE_TEXT * 400
    _inspect(app, text)
    delay = app.slider(key="inspect_delay")
    assert (delay.min, delay.max, delay.value) == (50, 2000, 500)
    chunk = app.radio(key="inspect_chunk")
    assert list(chunk.options) == ["8,192 chars (1x overlap)", "16,384 chars (2x overlap)"]
    chunk.set_value(16384).run()
    _no_errors(app)
    doubled = list(trace_chunks(build_redactor(Settings(chunk_size=16384)), text))
    assert {m.label: m.value for m in app.metric}["Passes"] == str(len(doubled))
    assert len(doubled) < 23  # twice the chunk: about half the passes


def test_inspect_redacts_with_the_chosen_style(app: AppTest) -> None:
    _inspect(app, f"key {AWS}")
    redacted_pane = _pass_block(app).split("<strong>Redacted segment</strong>")[1]
    redacted_pane = redacted_pane.split("<strong>Last ")[0]
    assert "[REDACTED]" in redacted_pane and AWS not in redacted_pane
