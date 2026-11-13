"""TAB scoring: per-annotator gold, union precision and entity-level recall."""

from __future__ import annotations

import numpy as np
import pytest
from benchmarks.tab_score import _KEYS, doc_counts, metrics


def _m(start, end, ident, ent, etype="PERSON"):
    return {
        "start_offset": start,
        "end_offset": end,
        "entity_type": etype,
        "identifier_type": ident,
        "entity_id": ent,
    }


DOC = {
    "text": "x" * 40,
    "annotations": {
        # annotator 1: entity e1 (direct) twice, e2 quasi, one NO_MASK mention
        "a1": {
            "entity_mentions": [
                _m(0, 5, "DIRECT", "e1"),
                _m(10, 15, "DIRECT", "e1"),
                _m(20, 25, "QUASI", "e2", "DATETIME"),
                _m(30, 35, "NO_MASK", "e3"),
            ]
        },
        # annotator 2: only the first mention, as direct
        "a2": {"entity_mentions": [_m(0, 5, "DIRECT", "e1")]},
    },
}


def test_counts_and_metrics() -> None:
    # redacts the first mention fully, half of the second, nothing else, plus 5 stray chars
    c, by_type = doc_counts(DOC, [(0, 5, "X"), (10, 12, "X"), (36, 40, "X"), (35, 36, "X")])
    assert c["gold"] == 15 + 5  # a1: 15 chars, a2: 5 chars; NO_MASK is not gold
    assert c["gold_hit"] == 7 + 5
    assert c["red"] == 12 and c["red_ok"] == 7  # union gold is 0-5, 10-15, 20-25
    assert (c["ent_d"], c["ent_d_ok"]) == (2, 1)  # e1 fails for a1 (second mention), ok for a2
    assert (c["ent_q"], c["ent_q_ok"]) == (1, 0)
    assert (c["pairs_d"], c["pairs_d_ok"]) == (2, 1)
    assert by_type["DATETIME"] == [5, 0]
    m = metrics(np.array([c[k] for k in _KEYS]))
    assert m["char_recall"] == pytest.approx(12 / 20)
    assert m["char_precision"] == pytest.approx(7 / 12)
    assert m["er_direct"] == pytest.approx(0.5)
    assert m["direct_protected"] == pytest.approx(0.5)


def test_nothing_redacted() -> None:
    c, _ = doc_counts(DOC, [])
    m = metrics(np.array([c[k] for k in _KEYS]))
    assert m["char_recall"] == 0 and m["char_precision"] == 0 and m["char_f1"] == 0
