"""Tests for the learned confidence calibrator."""

import json

import pytest

from safestream_redactor import Calibrator, EntityType, Redactor
from safestream_redactor.calibration import FEATURE_NAMES, features
from safestream_redactor.entities import Detection


def det(source="deterministic", conf=0.9, etype=EntityType.EMAIL, context=None):
    d = Detection(0, 4, "text", etype, conf, source=source)
    if context:
        d.meta["context"] = context
    return d


def test_feature_vector_shape_and_content():
    d = det(source="entropy", conf=0.6, etype=EntityType.SECRET, context="suppressed")
    f = features(d)
    assert len(f) == len(FEATURE_NAMES)
    assert f[FEATURE_NAMES.index("confidence")] == 0.6
    assert f[FEATURE_NAMES.index("source=entropy")] == 1.0
    assert f[FEATURE_NAMES.index("source=deterministic")] == 0.0
    assert f[FEATURE_NAMES.index("ctx_suppressed")] == 1.0
    assert f[FEATURE_NAMES.index("ctx_boosted")] == 0.0
    assert f[FEATURE_NAMES.index("structured")] == 0.0  # SECRET is not structured


def test_fit_separates_a_linearly_separable_signal():
    # true positives: structured, high confidence; false positives: entropy, low
    rows, labels = [], []
    for _ in range(50):
        rows.append(features(det(source="deterministic", conf=0.95, etype=EntityType.SSN)))
        labels.append(1)
        rows.append(features(det(source="entropy", conf=0.6, etype=EntityType.SECRET)))
        labels.append(0)
    cal = Calibrator.fit(rows, labels, epochs=500)
    tp_p = cal.predict_one(det(source="deterministic", conf=0.95, etype=EntityType.SSN))
    fp_p = cal.predict_one(det(source="entropy", conf=0.6, etype=EntityType.SECRET))
    assert tp_p > 0.6 > fp_p
    assert 0.0 <= fp_p <= 1.0 and 0.0 <= tp_p <= 1.0


def test_fit_is_deterministic():
    rows = [features(det(conf=c)) for c in (0.9, 0.5, 0.7, 0.3)]
    labels = [1, 0, 1, 0]
    a = Calibrator.fit(rows, labels, epochs=100)
    b = Calibrator.fit(rows, labels, epochs=100)
    assert a.weights == b.weights


def test_fit_rejects_bad_input():
    with pytest.raises(ValueError):
        Calibrator.fit([], [])
    with pytest.raises(ValueError):
        Calibrator.fit([features(det())], [1, 0])  # length mismatch
    with pytest.raises(ValueError):
        Calibrator.fit([[1.0, 2.0]], [1])  # wrong feature width


def test_predict_validates_width():
    cal = Calibrator([0.0] * (len(FEATURE_NAMES) + 1))
    with pytest.raises(ValueError):
        cal.predict([1.0, 2.0])


def test_constructor_rejects_wrong_weight_count():
    with pytest.raises(ValueError):
        Calibrator([0.0, 1.0])


def test_save_load_roundtrip(tmp_path):
    rows = [features(det(conf=c)) for c in (0.9, 0.4, 0.8, 0.2)]
    cal = Calibrator.fit(rows, [1, 0, 1, 0], epochs=50)
    p = tmp_path / "model.json"
    cal.save(p)
    loaded = Calibrator.load(p)
    assert loaded.weights == cal.weights
    assert loaded.predict_one(det()) == cal.predict_one(det())


def test_load_rejects_schema_mismatch(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"version": 1, "feature_names": ["nope"], "weights": [0.0]}))
    with pytest.raises(ValueError):
        Calibrator.load(p)


def test_load_rejects_non_list_weights(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"feature_names": list(FEATURE_NAMES), "weights": "x"}))
    with pytest.raises(ValueError):
        Calibrator.from_dict(json.loads(p.read_text()))


def test_redactor_applies_calibrator_before_thresholding():
    # a calibrator that forces every detection to ~0 probability suppresses all
    n = len(FEATURE_NAMES)
    kill = Calibrator([-50.0] + [0.0] * n)  # bias only, huge negative
    r = Redactor(calibrator=kill)
    assert r.detect("mail me at a@b.com and ssn 123-45-6789") == []
    # and one that forces ~1 keeps even a normally-subthreshold detection
    keep = Calibrator([50.0] + [0.0] * n)
    r2 = Redactor(calibrator=keep, min_confidence=0.9)
    assert r2.detect("mail a@b.com") != []
