"""Allow ``python -m safestream_redactor`` as an alias for the ``safestream`` CLI."""

import sys

from safestream_redactor.cli import main

sys.exit(main())
