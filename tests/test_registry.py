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


def test_bad_plugin_is_skipped(monkeypatch):
    class _Boom:
        def load(self):
            raise RuntimeError("boom")

    not_a_detector = _FakeEntryPoint(object())  # loads but isn't a Detector
    monkeypatch.setattr(registry, "entry_points", lambda group: [_Boom(), not_a_detector])
    assert registry.load_plugins() == []


def test_redactor_uses_plugins(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    out = Redactor().redact("launch code TOPSECRET now")
    assert out == "launch code [REDACTED] now"


def test_plugins_can_be_disabled(monkeypatch):
    monkeypatch.setattr(registry, "entry_points", lambda group: [_FakeEntryPoint(_PluginDetector)])
    out = Redactor(load_plugins=False).redact("launch code TOPSECRET now")
    assert out == "launch code TOPSECRET now"
