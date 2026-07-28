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

import logging
from importlib.metadata import entry_points

from safestream_redactor.detectors.base import Detector

PLUGIN_GROUP = "safestream_redactor.detectors"

logger = logging.getLogger(__name__)


def load_plugins(group: str = PLUGIN_GROUP) -> list[Detector]:
    """Instantiate every detector registered under ``group``.

    A plugin whose target is a class is instantiated with no arguments; one
    that is already a :class:`Detector` instance is used as-is. Plugins that
    fail to load or don't satisfy the :class:`Detector` protocol are skipped
    with a warning rather than crashing the whole pipeline — but never
    silently, since a missing tier means reduced redaction coverage.
    """
    detectors: list[Detector] = []
    for ep in entry_points(group=group):
        ep_name = getattr(ep, "name", repr(ep))
        try:
            obj = ep.load()
            candidate = obj() if isinstance(obj, type) else obj
        except Exception:
            logger.warning("detector plugin %r failed to load; skipping it", ep_name, exc_info=True)
            continue
        if isinstance(candidate, Detector):
            logger.debug("loaded detector plugin %r (%s)", ep_name, candidate.name)
            detectors.append(candidate)
        else:
            logger.warning(
                "detector plugin %r does not satisfy the Detector protocol; skipping it", ep_name
            )
    return detectors
