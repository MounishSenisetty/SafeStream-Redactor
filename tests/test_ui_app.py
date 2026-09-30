"""The Streamlit page, driven headlessly. Needs the [ui] extra; skipped otherwise."""

from __future__ import annotations

from collections.abc import Iterator

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
    assert metrics["Findings"] == "8" and metrics["Highest severity"] == "critical"
    table = app.dataframe[0].value
    assert list(table["Line:Col"])[:2] == ["1:46", "1:85"]
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
