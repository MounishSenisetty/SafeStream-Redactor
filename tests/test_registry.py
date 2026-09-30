"""Detector plugin-registry tests (entry-point discovery)."""

from safestream_redactor import EntityType, Redactor
from safestream_redactor.detectors import registry
from safestream_redactor.entities import Detection


class _PluginDetector:
    """A stand-in third-party detector that flags the literal 'TOPSECRET'."""

    name = "plugin"

    def detect(self, text: str) -> list[Detection]:
        out = []
        start = text.find("TOPSECRET")
        while start != -1:
            out.append(
                Detection(
                    start=start,
                    end=start + 9,
                    text="TOPSECRET",
                    entity_type=EntityType.CUSTOM,
                    confidence=1.0,
                    source=self.name,
                )
            )
            start = text.find("TOPSECRET", start + 1)
        return out


class _FakeEntryPoint:
    name = "fake"

    def __init__(self, obj):
        self._obj = obj

    def load(self):
        return self._obj


def test_load_plugins_instantiates_class(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    loaded = registry.load_plugins()
    assert len(loaded) == 1 and loaded[0].name == "plugin"


def test_load_plugins_accepts_instance(monkeypatch):
    monkeypatch.setattr(
        registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector())]
    )
    assert registry.load_plugins()[0].name == "plugin"


def test_bad_plugin_is_skipped_with_warning(monkeypatch, caplog):
    class _Boom:
        name = "boom"

        def load(self):
            raise RuntimeError("boom")

    not_a_detector = _FakeEntryPoint(object())  # loads but isn't a Detector
    monkeypatch.setattr(registry, "entry_points", lambda group: [_Boom(), not_a_detector])
    with caplog.at_level("WARNING", logger=registry.logger.name):
        assert registry.load_plugins() == []
    # a skipped plugin is a coverage loss and must be visible to operators
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 2
    assert "'boom'" in warnings[0].getMessage()
    assert "Detector protocol" in warnings[1].getMessage()


def test_plugin_constructor_failure_is_skipped_with_warning(monkeypatch, caplog):
    class _RaisesInInit:
        def __init__(self):
            raise ValueError("bad config")

    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_RaisesInInit)])
    with caplog.at_level("WARNING", logger=registry.logger.name):
        assert registry.load_plugins() == []
    assert any("failed to load" in r.getMessage() for r in caplog.records)


def test_redactor_uses_plugins_when_enabled(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    out = Redactor(load_plugins=True).redact("launch code TOPSECRET now")
    assert out == "launch code [REDACTED] now"


class _MustNotLoad:
    name = "evil"

    def load(self):  # pragma: no cover - the assertion is that this never runs
        raise AssertionError("plugin code was imported although loading is off")


def test_plugins_are_not_loaded_by_default(monkeypatch, caplog):
    # Installing a package must not inject code into every redaction run. The
    # skip warning reads entry-point metadata only; the plugin is never imported.
    monkeypatch.setattr(registry, "entry_points", lambda group: [_MustNotLoad()])
    monkeypatch.setattr(registry, "_unloaded_checked", False)
    with caplog.at_level("WARNING", logger="safestream_redactor"):
        assert Redactor().redact("launch code TOPSECRET now") == "launch code TOPSECRET now"
        Redactor()  # warned once per process, not once per Redactor
    skipped = [r for r in caplog.records if "installed but not loaded" in r.getMessage()]
    assert len(skipped) == 1
    assert "evil" in skipped[0].getMessage()


def test_no_skip_warning_without_installed_plugins(monkeypatch, caplog):
    monkeypatch.setattr(registry, "entry_points", lambda group: [])
    monkeypatch.setattr(registry, "_unloaded_checked", False)
    with caplog.at_level("WARNING", logger="safestream_redactor"):
        Redactor()
    assert not caplog.records


def test_plugins_enabled_from_config_and_cli(monkeypatch, tmp_path, capsys):
    from safestream_redactor.cli import main
    from safestream_redactor.config import redactor_from_config

    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    cfg = tmp_path / "p.toml"
    cfg.write_text("[plugins]\nenabled = true\n")
    assert "plugin" in redactor_from_config(cfg).detector_names
    cfg.write_text("[plugins]\nenabled = false\n")
    assert "plugin" not in redactor_from_config(cfg).detector_names

    src = tmp_path / "in.txt"
    src.write_text("launch code TOPSECRET now")
    assert main(["redact", str(src), "-o", "-", "--enable-plugins"]) == 0
    assert capsys.readouterr().out == "launch code [REDACTED] now"
    assert main(["redact", str(src), "-o", "-"]) == 0
    assert capsys.readouterr().out == "launch code TOPSECRET now"


def test_cli_surfaces_plugin_skip_warning(monkeypatch, tmp_path, capsys):
    # the library logs through a NullHandler; the CLI must still show the warning
    from safestream_redactor.cli import main

    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    monkeypatch.setattr(registry, "_unloaded_checked", False)
    src = tmp_path / "in.txt"
    src.write_text("nothing\n")
    assert main(["redact", str(src), "-o", "-"]) == 0
    err = capsys.readouterr().err
    assert "safestream: warning: 1 detector plugin(s) installed but not loaded" in err


def test_server_commands_accept_enable_plugins(monkeypatch):
    from safestream_redactor import cli

    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    seen = {}
    monkeypatch.setattr(
        "safestream_redactor.api.serve",
        lambda redactor, **kw: seen.__setitem__("serve", redactor.detector_names),
    )
    monkeypatch.setattr(
        "safestream_redactor.mcp_server.serve_stdio",
        lambda redactor: seen.__setitem__("mcp", redactor.detector_names),
    )
    monkeypatch.setattr("safestream_redactor.netguard.install", lambda: None)
    assert cli.main(["serve", "--port", "0", "--enable-plugins"]) == 0
    assert cli.main(["mcp-serve", "--enable-plugins"]) == 0
    assert "plugin" in seen["serve"] and "plugin" in seen["mcp"]


def test_plugins_can_be_disabled(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    out = Redactor(load_plugins=False).redact("launch code TOPSECRET now")
    assert out == "launch code TOPSECRET now"
