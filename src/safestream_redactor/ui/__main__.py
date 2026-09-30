"""``python -m safestream_redactor.ui``: start the web playground on 127.0.0.1:8501."""

import sys

from safestream_redactor.ui.launcher import launch

if __name__ == "__main__":
    sys.exit(launch())
