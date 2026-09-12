"""RedactionBench evaluation harness for SafeStream-Redactor.

This package is a **benchmark adapter** kept deliberately separate from the
``safestream_redactor`` core: it imports the shipped public API and never
modifies it. Its job is to load the Hugging Face ``RedactionBench/RedactionBench``
dataset, feed each document through the *real* production redaction pipeline
(the streaming/chunked engine by default), align the system's predictions with
the dataset's ground-truth annotations, and compute rigorous accuracy metrics.

Nothing here changes detector behaviour, thresholds, or patterns to chase a
score; the harness measures the architecture as it ships.

Modules
-------
``loader``   dataset acquisition (HF download or vendored files) + schema inspection
``adapter``  RedactionBench record  <->  SafeStream input/prediction
``metrics``  span-level and character-level scoring (P/R/F1, R-Score-style, accuracy)
``run``      the reproducible CLI (``inspect`` / ``run``)
"""

from __future__ import annotations

__all__ = ["adapter", "loader", "metrics"]
