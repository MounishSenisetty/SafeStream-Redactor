"""The engine's on_window observer: it reports every pass and never changes output."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from safestream_redactor import Redactor
from safestream_redactor.engine import WindowTrace


def _small(**kw) -> Redactor:
    # a tiny window (knowingly below the safe minimum) makes boundaries easy to hit
    options = {"types": ["email"], **kw}
    return Redactor(
        overlap=64, chunk_size=64, allow_unsafe_overlap=True, use_entropy=False, **options
    )


def _pieces(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _run(r: Redactor, text: str, size: int = 64) -> tuple[list, list[WindowTrace]]:
    traces: list[WindowTrace] = []
    segs = list(r.detect_stream(_pieces(text, size), on_window=traces.append))
    return segs, traces


def test_boundary_retreat_is_reported():
    # first pass buffers 128 chars and plans to emit 64; the email spans 58..69
    text = "w " * 29 + "bob@corp.io" + " y" * 100
    r = _small()
    segs, traces = _run(r, text)
    first = traces[0]
    assert (first.prefix_len, first.buffer_len, first.planned_emit) == (0, 128, 64)
    assert first.emit_len == 58  # pulled back to the email's start
    # the email is then emitted whole, at the start of the next segment
    assert segs[1][0].startswith("bob@corp.io")
    assert [d.text for d in segs[1][1]] == ["bob@corp.io"]


def test_pinned_pass_emits_nothing_and_is_still_reported():
    # a 100-char match from offset 0 fits the 128-char buffer and covers the planned
    # boundary at 64, so the boundary retreats to 0: the pass emits nothing
    r = _small(custom_patterns=[r"Z{100}"], types=[])
    text = "Z" * 100 + " tail" * 40
    segs, traces = _run(r, text)
    assert traces[0].emit_len == 0 and traces[0].planned_emit == 64
    assert "".join(s for s, _ in segs) == text
    assert segs[0][0].startswith("Z" * 100)  # emitted whole, once unpinned


def test_trace_invariants_on_real_settings():
    text = ("mail a@b.io key AKIAIOSFODNN7EXAMPLE ssn: 123-45-6789\n" * 2000)[:60_000]
    r = Redactor(chunk_size=8192)
    segs, traces = _run(r, text, size=8192)
    assert [t.pass_index for t in traces] == list(range(len(traces)))
    assert sum(t.emit_len for t in traces) == len(text)
    assert [t.final for t in traces].count(True) == 1 and traces[-1].final
    assert all(t.prefix_len <= r.overlap for t in traces)
    assert traces[0].prefix_len == 0 and traces[1].prefix_len == r.overlap
    emitted = [t.emit_len for t in traces if t.emit_len]
    assert emitted == [len(s) for s, _ in segs]
    # steady state: 8,192 left context + 8,192 emitted + 8,192 carried
    assert (traces[1].buffer_len, traces[1].planned_emit) == (16384, 8192)
    assert traces[1].dropped_in_prefix > 0  # context re-scan finds the prefix's entities


TOKENS = ["bob@corp.io", "plain words", "\n", "a@b.co", "zzzz"]


@settings(max_examples=60, derandomize=True, deadline=None)
@given(
    parts=st.lists(st.sampled_from(TOKENS), min_size=1, max_size=80),
    size=st.integers(min_value=1, max_value=97),
)
def test_observer_never_changes_output(parts, size):
    text = " ".join(parts)
    r = _small()
    plain = [(s, [(d.start, d.end) for d in ds]) for s, ds in r.detect_stream(_pieces(text, size))]
    traces: list[WindowTrace] = []
    observed = [
        (s, [(d.start, d.end) for d in ds])
        for s, ds in r.detect_stream(_pieces(text, size), on_window=traces.append)
    ]
    assert observed == plain
    assert sum(t.emit_len for t in traces) == len(text)
