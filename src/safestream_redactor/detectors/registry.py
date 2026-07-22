"""Third-party detector discovery via Python entry points.

Any installed package can contribute a detection tier by advertising an entry
point in the ``safestream_redactor.detectors`` group. The target may be either
a :class:`~safestream_redactor.detectors.base.Detector` instance or a
zero-argument class/factory that returns one::

    # in a plugin package's pyproject.toml
    [project.entry-points."safestream_redactor.detectors"]
    my_detector = "my_pkg.detectors:MyDetector"

:class:`~safestream_redactor.redactor.Redactor` loads these automatically
(``load_plugins=True`` by default), so installing the plugin is all a user
needs to do.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from safestream_redactor.detectors.base import Detector

PLUGIN_GROUP = "safestream_redactor.detectors"


def load_plugins(group: str = PLUGIN_GROUP) -> list[Detector]:
    """Instantiate every detector registered under ``group``.

    A plugin whose target is a class is instantiated with no arguments; one
    that is already a :class:`Detector` instance is used as-is. Plugins that
    fail to load or don't satisfy the :class:`Detector` protocol are skipped
    rather than crashing the whole pipeline.
    """
    detectors: list[Detector] = []
    for ep in entry_points(group=group):
        try:
            obj = ep.load()
        except Exception:
            continue
        candidate = obj() if isinstance(obj, type) else obj
        if isinstance(candidate, Detector):
            detectors.append(candidate)
    return detectors
