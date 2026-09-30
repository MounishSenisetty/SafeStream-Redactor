"""Suite-wide guards."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _no_leaked_address_space_limit() -> Iterator[None]:
    """Fail any test that leaves a kernel memory cap on the pytest process.

    ``--memory-limit`` lowers RLIMIT_AS (soft *and* hard) on the calling
    process, and a non-root process can never raise it back. A test that runs
    the real enforcement in-process therefore caps every test after it: the
    suite then dies with a MemoryError far from the cause, and only on
    interpreters/library versions that happen to allocate more. Real
    enforcement belongs in a forked child (see tests/test_memory_enforcement.py);
    in-process CLI tests must stub ``memory_budget.enforce_address_space_limit``.
    """
    if resource is None or not hasattr(resource, "RLIMIT_AS"):
        yield
        return
    before = resource.getrlimit(resource.RLIMIT_AS)
    yield
    after = resource.getrlimit(resource.RLIMIT_AS)
    if after != before:
        pytest.fail(
            f"test changed this process's RLIMIT_AS from {before} to {after}; stub "
            "memory_budget.enforce_address_space_limit or run the enforcement in a child",
            pytrace=False,
        )
