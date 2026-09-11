"""Explicit memory-budget admission control for the streaming engine.

Why this exists
---------------

The engine is already constant-memory: its working set is bounded by
``chunk_size + overlap + L_max`` characters, independent of input size
(``docs/FORMAL_MODEL.md``, Theorem 3). What it did *not* have was a way to say
"operate within N megabytes and refuse if you cannot". This module adds that.

It is **admission control**, not an allocator. Python gives no hook to cap heap
growth, so this module cannot *prevent* the interpreter from allocating; what it
can do — and does — is compute the engine's *estimated peak application working
set* for a given configuration and **fail closed** (raise
:class:`ResourceExhaustionError`) before starting when that estimate exceeds the
budget. It also derives a worker count that keeps the aggregate estimate under
the budget. That is a real, enforceable guarantee at the level the runtime
allows, and it is deliberately conservative (it over-estimates) so the true
peak stays under the number the operator asked for.

What the budget bounds, precisely
----------------------------------

The number here bounds the engine's **application-managed working set** — the
live Python strings the streaming pipeline holds at once — *not* process RSS.
RSS additionally includes the interpreter baseline (~15-40 MB), imported module
code, compiled regex objects, and any OS page cache, none of which scale with
input size. We report the interpreter baseline separately rather than pretend
the budget covers it; conflating the two would be the kind of false "constant
memory" claim ``docs/FORMAL_MODEL.md`` is careful to avoid.

Peak working-set model
-----------------------

At the busiest instant a single streaming worker holds, in characters:

* the rolling ``buffer`` (up to ``chunk_size + overlap``),
* the read-only ``prefix`` left-context (up to ``overlap``),
* the transient ``prefix + buffer`` string built for a detection pass
  (``chunk_size + 2*overlap``),
* the emitted ``segment`` and its ``redacted`` form (~``chunk_size`` each).

Summed, that is ``<= 3*chunk_size + 4*overlap`` live characters. We round the
model up to ``STREAM_CHAR_FACTOR * (chunk_size + overlap)`` characters to stay a
safe upper bound, times ``bytes_per_char`` for the string storage width CPython
picks for the input (1 for Latin-1-representable text, up to 4 for astral
Unicode). A per-worker fixed overhead covers compiled patterns and small
bookkeeping. The result is intentionally larger than reality; the budget is a
ceiling, so erring high is the safe direction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "AddressSpaceLimit",
    "BudgetPlan",
    "MemoryBudget",
    "ResourceExhaustionError",
    "enforce_address_space_limit",
    "estimate_interpreter_baseline",
    "format_size",
    "parse_size",
]

# Conservative upper bound on simultaneously-live characters as a multiple of
# (chunk_size + overlap). See module docstring for the derivation (worst instant
# is ~3*chunk + 4*overlap chars; 4x the sum bounds it).
STREAM_CHAR_FACTOR = 4

# Fixed per-worker Python-heap overhead not tied to the buffer: compiled regex
# objects for the tiers, the Redactor object graph, small per-call lists. Kept
# generous so the estimate errs toward fewer workers / earlier refusal.
PER_WORKER_FIXED = 12 * 1024 * 1024

# Default share of the budget held back as an unallocated safety reserve, so the
# estimate landing exactly on the limit still leaves slack for transient spikes
# (a single very long line, GC timing) we do not model per-character.
DEFAULT_RESERVE_FRACTION = 0.15


class ResourceExhaustionError(RuntimeError):
    """Raised when a configuration cannot run within the requested memory budget.

    This is the fail-closed signal: the engine refuses to start rather than
    silently allocate past the budget or fall back to loading the whole file.
    """


_UNITS: dict[str, int] = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
    # bare "k"/"m"/"g"/"t" are treated as the binary (…iB) sense, the
    # convention operators expect from ``--memory-limit 32m``.
    "k": 1024,
    "m": 1024**2,
    "g": 1024**3,
    "t": 1024**4,
}

_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]*)\s*$")


def parse_size(text: str | int) -> int:
    """Parse a human byte size (``"32MB"``, ``"32MiB"``, ``"1.5g"``, ``4096``).

    Decimal units (KB/MB/GB/TB) are powers of 1000; binary units (KiB/…/TiB and
    bare k/m/g/t) are powers of 1024. A plain number is bytes. Raises
    :class:`ValueError` on anything unparseable so a mistyped limit fails loudly
    rather than defaulting.
    """
    if isinstance(text, int):
        value = text
        if value <= 0:
            raise ValueError(f"memory size must be positive, got {text!r}")
        return value
    m = _SIZE_RE.match(text)
    if not m:
        raise ValueError(
            f"cannot parse memory size {text!r}; use e.g. '32MB', '256MiB', '1g', or a byte count"
        )
    number, unit = m.group(1), m.group(2).lower()
    factor = _UNITS.get(unit) if unit else 1
    if factor is None:
        valid = ", ".join(sorted({u.upper() for u in _UNITS}))
        raise ValueError(f"unknown size unit {m.group(2)!r} in {text!r}; valid units: {valid}")
    value = int(float(number) * factor)
    if value <= 0:
        raise ValueError(f"memory size must be positive, got {text!r}")
    return value


def format_size(num_bytes: int) -> str:
    """Human-readable binary size, e.g. ``format_size(33554432) == '32.0 MiB'``."""
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable, loop returns first


def estimate_interpreter_baseline() -> int:
    """Best-effort current process RSS in bytes, or a conservative estimate.

    Used only to *report* how much of a budget the interpreter itself already
    occupies (so an operator setting a very small ``--memory-limit`` gets an
    honest warning), never to enforce anything. Reads ``/proc/self/statm`` when
    present and otherwise returns a fixed conservative figure.
    """
    try:
        with open("/proc/self/statm") as f:
            pages = int(f.read().split()[1])  # resident set size, in pages
        import resource

        return pages * resource.getpagesize()
    except (OSError, ValueError, ImportError, IndexError):
        return 40 * 1024 * 1024


def _current_address_space_bytes() -> int | None:
    """Current process virtual address size (VSZ) in bytes, or ``None``.

    Reads field 0 of ``/proc/self/statm`` (total program size, in pages). This
    is the number :func:`enforce_address_space_limit` anchors the hard cap to,
    so growth is measured from where the process already is.
    """
    try:
        import resource

        with open("/proc/self/statm") as f:
            pages = int(f.read().split()[0])
        return pages * resource.getpagesize()
    except (OSError, ValueError, ImportError, IndexError):
        return None


@dataclass(slots=True, frozen=True)
class AddressSpaceLimit:
    """Outcome of trying to install a hard kernel memory cap (``RLIMIT_AS``).

    ``applied`` is True only when the kernel is now enforcing the cap; otherwise
    the caller keeps the pure-Python admission-control behaviour and ``reason``
    explains why enforcement was unavailable (non-POSIX platform, no
    ``/proc``, a rejected ``setrlimit``).
    """

    applied: bool
    mechanism: str  # "rlimit_as" when enforced, "none" otherwise
    cap_bytes: int | None
    reason: str


def enforce_address_space_limit(growth_bytes: int) -> AddressSpaceLimit:
    """Cap this process's address space at *current VSZ + ``growth_bytes``*.

    Backs ``--memory-limit`` with a real kernel boundary: once set,
    ``RLIMIT_AS`` makes the kernel fail any allocation (``mmap``/``brk``) that
    would grow the process past the cap, so the process fails **closed**
    (a :class:`MemoryError`, surfaced by the CLI as exit 3) instead of relying
    on Python-side accounting that cannot actually stop an allocation.

    The cap is anchored to the process's *current* virtual size, so
    ``growth_bytes`` is the additional working set the run is allowed — matching
    how :class:`MemoryBudget` defines the budget (an application working set,
    not total RSS). ``RLIMIT_AS`` bounds *virtual* address space, which can
    exceed resident memory (glibc arenas, thread stacks, mmap reservations), so
    the cap is deliberately conservative: it may refuse slightly *before* RSS
    reaches the budget, never after — the same "err toward earlier refusal"
    direction as the admission estimate.

    Graceful fallback: on platforms without ``resource``/``RLIMIT_AS`` (e.g.
    Windows) or when the current address size can't be read, nothing is enforced
    and ``applied=False`` is returned; the caller then keeps admission-only
    behaviour rather than failing. Never raises.

    This is process-wide and cannot be undone by lowering it further only; it is
    installed once, just before the streaming work begins.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - exercised only on non-POSIX
        return AddressSpaceLimit(False, "none", None, "resource module unavailable (non-POSIX)")
    rlimit_as = getattr(resource, "RLIMIT_AS", None)
    if rlimit_as is None:  # pragma: no cover - platform without RLIMIT_AS
        return AddressSpaceLimit(False, "none", None, "RLIMIT_AS unsupported on this platform")
    current = _current_address_space_bytes()
    if current is None:  # pragma: no cover - no /proc/self/statm
        return AddressSpaceLimit(
            False, "none", None, "could not read current address space (/proc/self/statm)"
        )
    cap = current + max(1, growth_bytes)
    soft, hard = resource.getrlimit(rlimit_as)
    # Only ever tighten: keep any pre-existing (e.g. container) hard limit that
    # is already lower than our computed cap.
    new_hard = cap if hard == resource.RLIM_INFINITY else min(cap, hard)
    new_soft = new_hard if soft == resource.RLIM_INFINITY else min(cap, new_hard, soft)
    new_soft = min(new_soft, new_hard)
    try:
        resource.setrlimit(rlimit_as, (new_soft, new_hard))
    except (ValueError, OSError) as exc:  # pragma: no cover - kernel refusal
        return AddressSpaceLimit(False, "none", None, f"setrlimit(RLIMIT_AS) rejected: {exc}")
    return AddressSpaceLimit(
        True,
        "rlimit_as",
        new_soft,
        f"address space capped at {format_size(new_soft)} "
        f"(current {format_size(current)} + budget {format_size(growth_bytes)})",
    )


@dataclass(slots=True, frozen=True)
class BudgetPlan:
    """The admitted configuration derived from a :class:`MemoryBudget`.

    Every field is a decision the engine will honour: ``workers`` is the number
    the budget permits (never more than requested), and ``per_worker_bytes`` is
    the estimated peak working set of each. ``headroom_bytes`` is what remains
    under the limit after the plan.
    """

    total_limit_bytes: int
    chunk_size: int
    overlap: int
    workers: int
    per_worker_bytes: int
    model_bytes: int
    reserve_bytes: int
    headroom_bytes: int

    @property
    def estimated_peak_bytes(self) -> int:
        """Estimated aggregate application working set this plan will use."""
        return self.workers * self.per_worker_bytes + self.model_bytes + self.reserve_bytes


@dataclass(slots=True)
class MemoryBudget:
    """An explicit application memory budget the engine must run within.

    Parameters
    ----------
    total_limit:
        The ceiling, as bytes or a human string (``"32MB"``). This bounds the
        estimated application working set (see module docstring), not process
        RSS.
    model_budget:
        Bytes carved out for an optional local model (NER/ONNX) loaded once and
        shared, kept out of the per-worker streaming budget. ``0`` when no model
        is used.
    reserve_fraction:
        Fraction of ``total_limit`` held unallocated as a safety reserve.
    bytes_per_char:
        Storage width to assume for input characters (1 for ASCII/Latin-1 logs,
        up to 4 for astral Unicode). The default of 1 matches log/config
        redaction; raise it for CJK/emoji-heavy corpora to keep the estimate an
        upper bound.
    per_worker_fixed:
        Fixed per-worker overhead (compiled patterns, object graph).
    """

    total_limit: int | str = field()
    model_budget: int | str = 0
    reserve_fraction: float = DEFAULT_RESERVE_FRACTION
    bytes_per_char: int = 1
    per_worker_fixed: int = PER_WORKER_FIXED

    def __post_init__(self) -> None:
        # Validate/normalize eagerly so a bad size string fails at construction.
        parse_size(self.total_limit)
        if self.model_budget:
            parse_size(self.model_budget)
        if not 0.0 <= self.reserve_fraction < 1.0:
            raise ValueError("reserve_fraction must be in [0, 1)")
        if self.bytes_per_char < 1:
            raise ValueError("bytes_per_char must be >= 1")

    # ``total_limit``/``model_budget`` accept a human string or an int; these
    # expose the normalized byte counts (parse_size is idempotent on an int).
    @property
    def limit(self) -> int:
        return parse_size(self.total_limit)

    @property
    def model_bytes(self) -> int:
        return parse_size(self.model_budget) if self.model_budget else 0

    # -- estimation ---------------------------------------------------------

    def per_worker_estimate(self, chunk_size: int, overlap: int) -> int:
        """Estimated peak working set of one streaming worker, in bytes."""
        chars = STREAM_CHAR_FACTOR * (chunk_size + overlap)
        return chars * self.bytes_per_char + self.per_worker_fixed

    @property
    def reserve_bytes(self) -> int:
        return int(self.limit * self.reserve_fraction)

    @property
    def allocatable_bytes(self) -> int:
        """Budget available to workers after model and reserve are set aside."""
        return self.limit - self.model_bytes - self.reserve_bytes

    # -- admission ----------------------------------------------------------

    def plan(
        self,
        chunk_size: int,
        overlap: int,
        *,
        requested_workers: int | None = None,
        max_workers: int | None = None,
    ) -> BudgetPlan:
        """Admit a configuration, or fail closed.

        Returns the :class:`BudgetPlan` the budget permits: the same
        ``chunk_size``/``overlap`` and a worker count no greater than
        ``requested_workers`` (and ``max_workers``, e.g. the CPU count) that
        keeps the estimated aggregate working set under ``total_limit``.

        Raises :class:`ResourceExhaustionError` when even a single worker at
        this ``chunk_size``/``overlap`` does not fit — the fail-closed path. The
        caller must not silently shrink buffers or load the whole file instead;
        it should surface the error.
        """
        if self.model_bytes >= self.limit:
            raise ResourceExhaustionError(
                f"model budget {format_size(self.model_bytes)} alone meets or exceeds the "
                f"total limit {format_size(self.limit)}; raise --memory-limit or disable "
                "the model tier"
            )
        per_worker = self.per_worker_estimate(chunk_size, overlap)
        allocatable = self.allocatable_bytes
        if per_worker > allocatable:
            # Fail closed: one worker's estimated working set does not fit.
            smaller = self._largest_fitting_chunk(overlap, allocatable)
            hint = (
                f" the largest chunk_size that fits is ~{format_size(smaller)}"
                if smaller
                else " reduce chunk_size/overlap or raise the limit"
            )
            raise ResourceExhaustionError(
                f"cannot run within {format_size(self.limit)}: one worker at "
                f"chunk_size={format_size(chunk_size)} overlap={format_size(overlap)} needs an "
                f"estimated {format_size(per_worker)} working set, but only "
                f"{format_size(allocatable)} is allocatable after model "
                f"({format_size(self.model_bytes)}) and reserve "
                f"({format_size(self.reserve_bytes)}).{hint}"
            )
        affordable = allocatable // per_worker
        workers = max(1, affordable)
        if requested_workers is not None:
            workers = min(workers, max(1, requested_workers))
        if max_workers is not None:
            workers = min(workers, max(1, max_workers))
        used = workers * per_worker + self.model_bytes + self.reserve_bytes
        return BudgetPlan(
            total_limit_bytes=self.limit,
            chunk_size=chunk_size,
            overlap=overlap,
            workers=workers,
            per_worker_bytes=per_worker,
            model_bytes=self.model_bytes,
            reserve_bytes=self.reserve_bytes,
            headroom_bytes=self.limit - used,
        )

    def _largest_fitting_chunk(self, overlap: int, allocatable: int) -> int:
        """Largest chunk_size whose single-worker estimate fits, or 0 if none."""
        budget_chars = (allocatable - self.per_worker_fixed) // self.bytes_per_char
        chunk = budget_chars // STREAM_CHAR_FACTOR - overlap
        return chunk if chunk > 0 else 0
