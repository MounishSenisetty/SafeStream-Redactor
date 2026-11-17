"""Delimited tables typed by their header row (CSV, TSV, semicolon- or pipe-separated).

A table's header names what each column holds, so ``Suresh Kumar,9876543210`` under
``name,phone`` is a person and a phone even though neither value says so on its own.
The header is the **first line of the input**, which a streaming window usually
cannot see, so this tier does not find it itself: the
:class:`~safestream_redactor.redactor.Redactor` reads the first line once per run
(whole text, stream, file, or each parallel worker) and builds a
:class:`ColumnDetector` that knows it. The header is then a fixed parameter of the
run, and the detector is a pure function of each window like every other tier.

A cell counts only when the start of its row lies at most ``row_window`` characters
before it (so its column number can be read inside any window holding the cell),
the cell is at most :data:`MAX_CELL` characters, and its value passes the same
validator the structured-field tier applies to a field of that name. Rows longer
than ``row_window`` are skipped past that point, consistently in every window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.structured import _valid, field_type
from safestream_redactor.entities import Detection, EntityType

MAX_CELL = 128
# the header is read from at most this many characters of the input
MAX_HEADER = 4096
_DELIMITERS = ("\t", ",", ";", "|")
_HEADER_CELL = re.compile(r"[A-Za-z][A-Za-z0-9 _.()/#'-]{0,47}")
# column names the structured-field vocabulary leaves to the URL-query table
_EXTRA_TYPES = {
    "email": EntityType.EMAIL,
    "e-mail": EntityType.EMAIL,
    "emailaddress": EntityType.EMAIL,
    "emailid": EntityType.EMAIL,
    "mail": EntityType.EMAIL,
    "ip": EntityType.IPV4,
    "ipaddress": EntityType.IPV4,
}
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


@dataclass(frozen=True)
class ColumnSpec:
    """A header: the delimiter, and each column's name and entity type (or None)."""

    delimiter: str
    names: tuple[str, ...]
    types: tuple[EntityType | None, ...]


def _split(line: str, delimiter: str) -> list[tuple[int, int]]:
    """Cell spans of one row, honouring double quotes (no multi-line cells)."""
    spans: list[tuple[int, int]] = []
    start, quoted = 0, False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == delimiter and not quoted:
            spans.append((start, i))
            start = i + 1
    spans.append((start, len(line)))
    return spans


def _column_type(name: str) -> EntityType | None:
    norm = re.sub(r"[^a-z-]", "", name.lower())
    return field_type(name) or _EXTRA_TYPES.get(norm) or _EXTRA_TYPES.get(norm.replace("-", ""))


def header_spec(text: str) -> ColumnSpec | None:
    """The table header that ``text`` starts with, or ``None``.

    The first line must split on one delimiter into two or more cells that all
    read as column names, and at least one name must announce personal data.
    """
    end = text.find("\n", 0, MAX_HEADER)
    if end < 0:
        return None  # a single line (or a header longer than MAX_HEADER) is no table
    line = text[:end].rstrip("\r").lstrip("﻿")
    counts = {d: line.count(d) for d in _DELIMITERS}
    delimiter = max(_DELIMITERS, key=lambda d: counts[d])
    if counts[delimiter] == 0:
        return None
    names = []
    for a, b in _split(line, delimiter):
        cell = line[a:b].strip().strip('"').strip()
        if not _HEADER_CELL.fullmatch(cell):
            return None
        names.append(cell)
    types = tuple(_column_type(n) for n in names)
    if not any(types):
        return None
    return ColumnSpec(delimiter, tuple(names), types)


def _cell_ok(etype: EntityType, value: str, name: str) -> bool:
    if etype is EntityType.EMAIL:
        return "@" in value and " " not in value
    if etype is EntityType.IPV4:
        return bool(_IPV4.fullmatch(value))
    return _valid(etype, value, name, line=True)


class ColumnDetector:
    """Redacts the cells of typed columns in the rows below a known header."""

    name = "columns"

    def __init__(self, spec: ColumnSpec, row_window: int = MAX_HEADER) -> None:
        self.spec = spec
        self.row_window = max(1, row_window)
        # reads back to its row's start (plus the newline before it) and one
        # character past a cell to see that it ended
        self.requirements = StreamingRequirements(
            max_span=MAX_CELL, left_context=self.row_window + 1, right_context=1
        )

    def detect(self, text: str) -> list[Detection]:
        spec, found = self.spec, []
        delimiter = spec.delimiter
        pos = text.find("\n")
        while pos >= 0:
            row = pos + 1
            nxt = text.find("\n", row)
            line_end = len(text) if nxt < 0 else nxt
            # only the part of the row whose cells start inside the row window
            stop = min(line_end, row + self.row_window + MAX_CELL + 1)
            line = text[row:stop]
            for column, (a, b) in enumerate(_split(line, delimiter)):
                if a > self.row_window:
                    break
                if column >= len(spec.types) or spec.types[column] is None:
                    continue
                if row + b == stop and stop < line_end:
                    break  # the cell runs past what may be read: not decidable here
                cell = line[a:b].rstrip("\r")
                lead = len(cell) - len(cell.lstrip())  # offset of the value in the cell
                value = cell.strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    inner = value[1:-1]
                    lead += 1 + len(inner) - len(inner.lstrip())
                    value = inner.strip()
                etype = spec.types[column]
                if etype is None or not value or len(value) > MAX_CELL:
                    continue
                if not _cell_ok(etype, value, spec.names[column]):
                    continue
                start = row + a + lead
                found.append(
                    Detection(
                        start=start,
                        end=start + len(value),
                        text=value,
                        entity_type=etype,
                        confidence=0.8,
                        source=self.name,
                        meta={"field": spec.names[column][:32]},
                    )
                )
            pos = nxt
        return found
