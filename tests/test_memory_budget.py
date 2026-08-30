"""Memory-budget admission control: parsing, planning, and fail-closed refusal."""

from __future__ import annotations

import pytest

from safestream_redactor.memory_budget import (
    MemoryBudget,
    ResourceExhaustionError,
    format_size,
    parse_size,
)


class TestParseSize:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("1024", 1024),
            (4096, 4096),
            ("1KB", 1000),
            ("1KiB", 1024),
            ("32MB", 32_000_000),
            ("32MiB", 32 * 1024 * 1024),
            ("1g", 1024**3),  # bare unit is binary
            ("1.5GiB", int(1.5 * 1024**3)),
            ("  8 mib ", 8 * 1024 * 1024),
        ],
    )
    def test_parses(self, text: str | int, expected: int) -> None:
        assert parse_size(text) == expected

    @pytest.mark.parametrize("bad", ["", "MB", "-5MB", "0", "12 quux", "12.3.4MB"])
    def test_rejects(self, bad: str) -> None:
        with pytest.raises(ValueError):
            parse_size(bad)

    def test_rejects_nonpositive_int(self) -> None:
        with pytest.raises(ValueError):
            parse_size(0)


def test_format_size_roundtrip_readable() -> None:
    assert format_size(32 * 1024 * 1024) == "32.0 MiB"
    assert format_size(1024) == "1.0 KiB"
    assert format_size(512) == "512 B"


class TestBudgetPlanning:
    def test_generous_budget_admits_and_scales_workers(self) -> None:
        budget = MemoryBudget("512MB")
        plan = budget.plan(64 * 1024, 8 * 1024, requested_workers=4, max_workers=8)
        assert plan.workers == 4  # requested honoured under a generous budget
        assert plan.estimated_peak_bytes <= budget.limit
        assert plan.headroom_bytes >= 0

    def test_tight_budget_reduces_workers(self) -> None:
        # A budget that fits a couple of workers but not eight.
        budget = MemoryBudget("64MB")
        plan = budget.plan(64 * 1024, 8 * 1024, requested_workers=8, max_workers=8)
        assert 1 <= plan.workers < 8
        assert plan.estimated_peak_bytes <= budget.limit

    def test_fail_closed_when_single_worker_cannot_fit(self) -> None:
        # 4 MB budget cannot hold a 64 MB chunk's working set.
        budget = MemoryBudget("4MB")
        with pytest.raises(ResourceExhaustionError) as exc:
            budget.plan(64 * 1024 * 1024, 8 * 1024)
        # error is actionable: names the limit and suggests a smaller chunk
        assert "4.0 MiB" in str(exc.value)
        assert "chunk_size" in str(exc.value)

    def test_model_budget_carved_out(self) -> None:
        budget = MemoryBudget("128MB", model_budget="64MB")
        plan = budget.plan(64 * 1024, 8 * 1024, requested_workers=4)
        assert plan.model_bytes == 64_000_000
        # workers must fit in what remains after the model + reserve
        assert plan.estimated_peak_bytes <= budget.limit

    def test_model_exceeding_total_fails_closed(self) -> None:
        budget = MemoryBudget("32MB", model_budget="64MB")
        with pytest.raises(ResourceExhaustionError):
            budget.plan(64 * 1024, 8 * 1024)

    def test_bytes_per_char_raises_estimate(self) -> None:
        ascii_est = MemoryBudget("128MB", bytes_per_char=1).per_worker_estimate(64 * 1024, 8 * 1024)
        astral_est = MemoryBudget("128MB", bytes_per_char=4).per_worker_estimate(
            64 * 1024, 8 * 1024
        )
        assert astral_est > ascii_est

    def test_reserve_fraction_validated(self) -> None:
        with pytest.raises(ValueError):
            MemoryBudget("64MB", reserve_fraction=1.0)

    def test_larger_chunk_hint_is_positive_when_room_exists(self) -> None:
        budget = MemoryBudget("32MB")
        # A chunk slightly too big to fit should still yield a "largest fitting" hint.
        with pytest.raises(ResourceExhaustionError) as exc:
            budget.plan(16 * 1024 * 1024, 8 * 1024)
        assert "largest chunk_size that fits" in str(exc.value)
