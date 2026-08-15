"""Learned confidence calibration for detections.

The built-in confidences are hand-set constants (0.95 for an email, 0.6 for the
entropy tier, and so on). They order detections sensibly but they are not
probabilities: a "0.9" credit-card match and a "0.9" entropy secret are not
equally likely to be real. A reviewer will object that ``min_confidence`` is
therefore an arbitrary knob.

This module removes that objection. A :class:`Calibrator` is a small logistic
regression that maps a detection's *local* features — its raw confidence, which
tier produced it, whether context boosted or suppressed it, and a coarse
entity-type bucket — to a calibrated probability that the detection is a true
positive, learned from labeled data. It has no third-party dependencies (the
logistic fit is a few dozen lines of plain Python), so the core install stays
dependency-free.

Crucially, every feature is a function of the detection alone, not of any wider
context, so applying a calibrator preserves the streaming/parallel equivalence
guarantees (docs/FORMAL_MODEL.md): calibration changes the reference pipeline
``Π`` but not the equality between ``S_w``/``P_{w,k}`` and ``Π``.

Train one with ``benchmarks/calibrate.py`` against a labeled corpus, save it to
JSON, and point a :class:`~safestream_redactor.redactor.Redactor` at it via the
``calibrator=`` argument or a ``[calibration] model = "…"`` config section.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Sequence
from dataclasses import dataclass

from safestream_redactor.entities import Detection, EntityType

# Detection ``source`` tiers we one-hot. An unknown source contributes no tier
# indicator (its signal is carried by the bias term and the other features).
_SOURCES: tuple[str, ...] = ("deterministic", "entropy", "contextual", "ner", "custom")

# Structured PII has a checkable shape (checksums, grammars); free-form secrets
# and NER spans do not. The distinction is predictive of precision, so it is a
# feature.
_STRUCTURED: frozenset[EntityType] = frozenset(
    {
        EntityType.EMAIL,
        EntityType.SSN,
        EntityType.CREDIT_CARD,
        EntityType.IPV4,
        EntityType.IPV6,
        EntityType.PHONE,
    }
)

# Names of the feature vector produced by :func:`features`, in order. The bias
# term is implicit (prepended during fit/predict), so it is not listed here.
FEATURE_NAMES: tuple[str, ...] = (
    "confidence",
    *(f"source={s}" for s in _SOURCES),
    "ctx_boosted",
    "ctx_suppressed",
    "structured",
)


def features(det: Detection) -> list[float]:
    """The fixed, detection-local feature vector (no bias term)."""
    context = det.meta.get("context", "")
    return [
        det.confidence,
        *(1.0 if det.source == s else 0.0 for s in _SOURCES),
        1.0 if context == "boosted" else 0.0,
        1.0 if context == "suppressed" else 0.0,
        1.0 if det.entity_type in _STRUCTURED else 0.0,
    ]


def _sigmoid(z: float) -> float:
    # numerically stable logistic function
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass(slots=True)
class Calibrator:
    """A logistic model over :func:`features`, mapping a detection to P(true).

    ``weights[0]`` is the bias; ``weights[1:]`` align with :data:`FEATURE_NAMES`.
    Build one with :meth:`fit`, apply it with :meth:`predict` /
    :meth:`predict_one`, and persist it with :meth:`save` / :meth:`load`.
    """

    weights: list[float]

    def __post_init__(self) -> None:
        expected = len(FEATURE_NAMES) + 1
        if len(self.weights) != expected:
            raise ValueError(
                f"calibrator expects {expected} weights (bias + {len(FEATURE_NAMES)} "
                f"features), got {len(self.weights)}"
            )

    # ------------------------------------------------------------------
    # training
    # ------------------------------------------------------------------

    @classmethod
    def fit(
        cls,
        rows: Sequence[Sequence[float]],
        labels: Sequence[int],
        *,
        l2: float = 1.0,
        lr: float = 0.1,
        epochs: int = 2000,
    ) -> Calibrator:
        """Train by full-batch gradient descent on feature rows and 0/1 labels.

        ``rows`` are vectors from :func:`features` (without the bias term).
        Training is deterministic — same data in, same weights out — so a model
        committed to a repo reproduces exactly. ``l2`` is the ridge penalty
        (not applied to the bias); ``lr`` and ``epochs`` are the step size and
        iteration count.
        """
        if len(rows) != len(labels):
            raise ValueError("rows and labels must be the same length")
        if not rows:
            raise ValueError("cannot fit a calibrator on an empty dataset")
        n_feat = len(FEATURE_NAMES)
        if any(len(r) != n_feat for r in rows):
            raise ValueError(f"every feature row must have {n_feat} values")

        n = len(rows)
        w = [0.0] * (n_feat + 1)  # index 0 is the bias
        for _ in range(epochs):
            grad = [0.0] * (n_feat + 1)
            for row, y in zip(rows, labels, strict=True):
                z = w[0] + sum(wi * xi for wi, xi in zip(w[1:], row, strict=True))
                err = _sigmoid(z) - y
                grad[0] += err
                for j, xi in enumerate(row, start=1):
                    grad[j] += err * xi
            w[0] -= lr * grad[0] / n
            for j in range(1, n_feat + 1):
                w[j] -= lr * (grad[j] / n + l2 * w[j] / n)
        return cls(w)

    # ------------------------------------------------------------------
    # inference
    # ------------------------------------------------------------------

    def predict(self, row: Sequence[float]) -> float:
        """Calibrated probability for a raw feature row (without bias term)."""
        if len(row) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(row)}")
        z = self.weights[0] + sum(wi * xi for wi, xi in zip(self.weights[1:], row, strict=True))
        return _sigmoid(z)

    def predict_one(self, det: Detection) -> float:
        """Calibrated probability that ``det`` is a true positive."""
        return self.predict(features(det))

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "feature_names": list(FEATURE_NAMES),
            "weights": self.weights,
        }

    def save(self, path: str | os.PathLike[str]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Calibrator:
        names = data.get("feature_names")
        if names != list(FEATURE_NAMES):
            raise ValueError(
                "calibrator feature schema mismatch: the model was trained "
                "against a different feature set than this version defines"
            )
        weights = data["weights"]
        if not isinstance(weights, list):
            raise ValueError("calibrator 'weights' must be a list")
        return cls([float(w) for w in weights])

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> Calibrator:
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))
