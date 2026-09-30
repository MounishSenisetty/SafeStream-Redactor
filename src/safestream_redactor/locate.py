"""Streaming line/column positions for findings.

Shared by every surface that reports a finding's location (the ``detect`` CLI,
SARIF output, the web UI) so they all agree on what "line 3, column 7" means:
1-based, counted in Unicode code points, with ``\\n`` as the line break (a
``\\r\\n`` pair therefore ends one line, and a lone ``\\r`` does not).
"""

from __future__ import annotations


class LineTracker:
    """Map absolute character offsets in a stream to 1-based (line, column).

    Fed segment by segment, in order, with the (sorted) offsets inside each, so
    locating every finding costs one pass over the text — no need to hold the
    input to compute positions after the fact.
    """

    def __init__(self) -> None:
        self._line = 1
        self._line_start = 0  # absolute offset of the current line's first char
        self._pos = 0  # absolute offset scanned up to

    def locate(self, segment: str, seg_offset: int, abs_offset: int) -> tuple[int, int]:
        i = self._pos - seg_offset
        stop = abs_offset - seg_offset
        while (nl := segment.find("\n", i, stop)) != -1:
            self._line += 1
            self._line_start = seg_offset + nl + 1
            i = nl + 1
        self._pos = abs_offset
        return self._line, abs_offset - self._line_start + 1

    def finish(self, segment: str, seg_offset: int) -> None:
        """Account for the rest of ``segment`` before the next one arrives."""
        self.locate(segment, seg_offset, seg_offset + len(segment))
