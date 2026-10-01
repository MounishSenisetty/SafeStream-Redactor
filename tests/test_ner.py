"""NER tier tests using an injected fake spaCy (no real extra required).

The important property under test is that the detector pickles as config only
(model name + confidence) and reloads the model on unpickle, so the
multiprocessing scheduler can ship it to workers without serializing a large
model object.
"""

import itertools
import pickle
import sys
import types

import pytest

from safestream_redactor.entities import EntityType


class _FakeEnt:
    def __init__(self, label, start, end, text):
        self.label_ = label
        self.start_char = start
        self.end_char = end
        self.text = text


class _FakeDoc:
    def __init__(self, ents):
        self.ents = ents


class _FakeNLP:
    def __call__(self, text):
        ents = []
        idx = text.find("Alice")
        if idx != -1:
            ents.append(_FakeEnt("PERSON", idx, idx + 5, "Alice"))
        return _FakeDoc(ents)


@pytest.fixture(autouse=True)
def _fresh_model_cache(monkeypatch):
    # loaded models are cached per process; give each test its own cache so a
    # fake pipeline never leaks between tests
    import safestream_redactor.detectors.ner as ner

    monkeypatch.setattr(ner, "_MODELS", {})


@pytest.fixture
def fake_spacy(monkeypatch):
    mod = types.ModuleType("spacy")
    mod.loads = []  # type: ignore[attr-defined]

    def load(name, exclude=None):
        mod.loads.append(name)  # type: ignore[attr-defined]
        return _FakeNLP()

    mod.load = load  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "spacy", mod)
    return mod


def _detector(model="fake-model"):
    from safestream_redactor.detectors.ner import NERDetector

    return NERDetector(model=model)


def test_ner_detects_via_model(fake_spacy):
    dets = _detector().detect("hello Alice here")
    assert len(dets) == 1
    assert dets[0].entity_type is EntityType.PERSON
    assert dets[0].text == "Alice"


def test_getstate_carries_config_not_the_model(fake_spacy):
    det = _detector()
    state = det.__getstate__()
    assert state == {"model": "fake-model", "confidence": 0.7}
    assert "_nlp" not in state  # the heavy model object is not serialized


def test_pickle_roundtrip_reloads_model(fake_spacy):
    det = _detector()
    restored = pickle.loads(pickle.dumps(det))
    assert restored._model == "fake-model"
    # the reloaded detector is fully functional
    assert restored.detect("ping Alice")[0].entity_type is EntityType.PERSON


def test_missing_spacy_raises_helpful_error(monkeypatch):
    # simulate the extra not being installed
    monkeypatch.setitem(sys.modules, "spacy", None)
    from safestream_redactor.detectors.ner import NERDetector

    with pytest.raises(ImportError, match=r"pip install safestream-redactor\[ner\]"):
        NERDetector()


def test_missing_model_fails_closed_with_download_hint(monkeypatch):
    from safestream_redactor.detectors.ner import NERDetector, NERUnavailableError

    mod = types.ModuleType("spacy")

    def load(name, exclude=None):
        raise OSError(f"[E050] Can't find model '{name}'.")

    mod.load = load  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "spacy", mod)
    with pytest.raises(NERUnavailableError, match=r"python -m spacy download en_core_web_sm"):
        NERDetector()


def test_model_is_loaded_once_per_process(fake_spacy):
    from safestream_redactor import Redactor

    Redactor()
    Redactor()
    assert fake_spacy.loads == ["en_core_web_sm"]


def test_ner_is_on_by_default_and_can_be_turned_off(fake_spacy):
    from safestream_redactor import Redactor

    assert "ner" in Redactor().detector_names
    # like the other name tiers, it runs whatever the type filter says
    assert "ner" in Redactor(types=["email"]).detector_names
    assert "ner" not in Redactor(use_ner=False).detector_names
    assert Redactor().redact("ping Alice now") == "ping [REDACTED] now"


class _BoundedNLP(_FakeNLP):
    """Fake pipeline that, like spaCy, refuses texts over ``max_length``."""

    max_length = 1_000_000

    def __call__(self, text):
        if len(text) > self.max_length:
            raise ValueError("[E088] Text exceeds maximum")
        return super().__call__(text)


def test_long_text_is_read_in_pieces_and_straddlers_are_reported_once(monkeypatch):
    import safestream_redactor.detectors.ner as ner

    monkeypatch.setattr(ner, "_load_model", lambda model: _BoundedNLP())
    # a newline-free text far over spaCy's limit, with "Alice" placed so it
    # straddles piece boundaries, and one on each side of them
    text = list("x " * 750_000)
    expected = []
    for at in (5, ner._PIECE - 2, 2 * ner._PIECE + 1, 1_400_000):
        text[at : at + 5] = "Alice"
        expected.append(at)
    text = "".join(text)
    dets = ner.NERDetector().detect(text)
    assert sorted(d.start for d in dets) == expected
    assert all(text[d.start : d.end] == "Alice" == d.text for d in dets)


def test_over_long_entity_is_covered_by_bounded_spans(monkeypatch):
    import safestream_redactor.detectors.ner as ner

    class _OneLongEnt:
        def __call__(self, text):
            return _FakeDoc([_FakeEnt("ORG", 0, len(text), text)])

    monkeypatch.setattr(ner, "_load_model", lambda model: _OneLongEnt())
    text = "Z" * 1000
    dets = ner.NERDetector().detect(text)
    assert all(d.end - d.start <= ner._MAX_SPAN for d in dets)
    # consecutive spans cover the whole entity, with no gap
    assert dets[0].start == 0 and dets[-1].end == len(text)
    assert all(a.end == b.start for a, b in itertools.pairwise(dets))


def test_cli_fails_closed_without_the_model_and_runs_with_no_ner(monkeypatch, tmp_path, capsys):
    from safestream_redactor.cli import main

    mod = types.ModuleType("spacy")

    def load(name, exclude=None):
        raise OSError(f"[E050] Can't find model '{name}'.")

    mod.load = load  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "spacy", mod)
    src = tmp_path / "in.txt"
    src.write_text("mail bob@x.io\n")
    assert main(["redact", str(src), "-o", "-"]) == 1
    assert "spacy download en_core_web_sm" in capsys.readouterr().err
    assert main(["redact", str(src), "-o", "-", "--no-ner"]) == 0
    assert capsys.readouterr().out == "mail [REDACTED]\n"
    # the servers refuse to start rather than serve without name redaction
    assert main(["serve", "--port", "0"]) == 1
    assert "spacy download en_core_web_sm" in capsys.readouterr().err


def test_config_can_turn_the_tier_off_and_the_cli_back_on(fake_spacy, tmp_path):
    from safestream_redactor.cli import _build_parser, _build_redactor
    from safestream_redactor.config import redactor_from_config

    cfg = tmp_path / "p.toml"
    cfg.write_text("[detection]\nuse_ner = false\n")
    assert "ner" not in redactor_from_config(cfg).detector_names
    args = _build_parser().parse_args(["detect", "-", "--config", str(cfg), "--ner"])
    assert "ner" in _build_redactor(args).detector_names


def test_ner_flags_are_mutually_exclusive(capsys):
    from safestream_redactor.cli import main

    with pytest.raises(SystemExit):
        main(["detect", "-", "--ner", "--no-ner"])


def test_spacy_span_never_displaces_a_rule_based_match(monkeypatch):
    # spaCy's boundaries are approximate: on CSV rows it tagged "kowalski,+53" as
    # one entity, swallowing the head of a phone number. Plain overlap resolution
    # let that 0.7 span beat the phone match, and " 338 462 4078" went out in the
    # clear. Rule-based spans must stay whole; spaCy only fills the gaps.
    import safestream_redactor.detectors.ner as ner
    from safestream_redactor import Redactor

    row = "5544,wei kowalski,+53 338 462 4078,660-69-3922"

    class _SloppyNLP:
        def __call__(self, text):
            at = text.find("kowalski,+53")
            ents = [] if at == -1 else [_FakeEnt("PERSON", at, at + 12, "kowalski,+53")]
            return _FakeDoc(ents)

    monkeypatch.setattr(ner, "_load_model", lambda model: _SloppyNLP())
    without = Redactor(use_ner=False)
    with_ner = Redactor()
    assert "338 462 4078" not in without.redact(row)
    out = with_ner.redact(row)
    assert "338 462 4078" not in out and "4078" not in out
    assert "kowalski" not in out  # the name part is still redacted

    def covered(dets):
        return {i for d in dets for i in range(d.start, d.end)}

    # turning the tier on only ever adds redacted characters
    assert covered(without.detect(row)) <= covered(with_ner.detect(row))
    dets = sorted(with_ner.detect(row), key=lambda d: d.start)
    assert all(a.end <= b.start for a, b in itertools.pairwise(dets))
    clipped = [d for d in dets if d.source == "ner"]
    assert [d.text for d in clipped] == ["kowalski,"]  # up to where the phone begins
    assert clipped[0].meta["clipped"] == "true"
