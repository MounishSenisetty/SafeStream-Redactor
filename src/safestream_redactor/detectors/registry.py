"""Third-party detector discovery via Python entry points.

Any installed package can contribute a detection tier by advertising an entry
point in the ``safestream_redactor.detectors`` group. The target may be either
a :class:`~safestream_redactor.detectors.base.Detector` instance or a
zero-argument class/factory that returns one::

    # in a plugin package's pyproject.toml
    [project.entry-points."safestream_redactor.detectors"]
    my_detector = "my_pkg.detectors:MyDetector"

Loading is **opt-in**: a plugin's code runs with full process privileges
inside a tool that handles secrets, so merely *installing* a package (perhaps
as a transitive dependency) must not inject code into every redaction run.
Enable it with ``Redactor(load_plugins=True)``, the CLI's ``--enable-plugins``,
or ``[plugins] enabled = true`` in a policy file.

When plugins are installed but loading is off, a one-time warning names them:
the redactor is then running with fewer tiers than the user may expect, and
reduced coverage must never be silent. Discovery for that warning reads only
entry-point *metadata*; no plugin code is imported.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from safestream_redactor.detectors.base import Detector

PLUGIN_GROUP = "safestream_redactor.detectors"

logger = logging.getLogger(__name__)

_unloaded_checked = False


def warn_if_plugins_skipped(group: str = PLUGIN_GROUP) -> None:
    """Warn (once per process) if detector plugins are installed but not loaded."""
    global _unloaded_checked
    if _unloaded_checked:
        return
    _unloaded_checked = True
    names = sorted(getattr(ep, "name", repr(ep)) for ep in entry_points(group=group))
    if names:
        logger.warning(
            "%d detector plugin(s) installed but not loaded (%s): plugin loading is "
            "opt-in. Enable it with --enable-plugins, [plugins] enabled = true, or "
            "Redactor(load_plugins=True) if you trust them.",
            len(names),
            ", ".join(names),
        )


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
