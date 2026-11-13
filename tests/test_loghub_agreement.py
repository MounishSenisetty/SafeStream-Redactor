"""Agreement statistics for the second annotator of the Loghub template labels."""

from __future__ import annotations

import numpy as np
import pytest
from benchmarks.loghub_agreement import _mark, kappa, kappa_with_interval, read_sheet, slot_pairs


def test_kappa_perfect_and_chance() -> None:
    assert kappa(np.diag([5.0, 3.0, 2.0])) == 1.0
    # both annotators always say "none": no disagreement possible, kappa defined as 1
    assert kappa(np.array([[4.0, 0, 0], [0, 0, 0], [0, 0, 0]])) == 1.0
    # independent marginals: observed agreement equals chance agreement
    assert kappa(np.array([[1.0, 1.0], [1.0, 1.0]])) == pytest.approx(0.0)


def test_mark_shows_one_slot() -> None:
    t = "Accepted password for <*> from <*> port <*> ssh2"
    assert _mark(t, 2) == "Accepted password for <*> from [[<*>]] port <*> ssh2"


def test_slot_pairs_and_interval() -> None:
    first = {"E1": {"slots": ["USER", "HOST", None]}, "E2": {"slots": ["HOST"]}}
    second = {"E1": {"slots": [None, "HOST", None]}, "E2": {"slots": ["HOST"]}}
    pairs = slot_pairs(first, second, ["E1", "E2", "E3"])
    assert [(t, a, b) for t, a, b in pairs] == [
        ("E1", 2, 0),
        ("E1", 1, 1),
        ("E1", 0, 0),
        ("E2", 1, 1),
    ]
    res = kappa_with_interval(pairs, resamples=50)
    assert res["slots"] == 4 and res["templates"] == 2
    assert res["observed_agreement"] == 0.75
    assert res["confusion_first_rows_second_cols"]["USER"]["none"] == 1


def test_read_sheet(tmp_path) -> None:
    p = tmp_path / "s.csv"
    p.write_text(
        "# comment\ncorpus,template_id,slot,template,label\n"
        "loghub_ssh,E1,1,x [[<*>]] y <*>,user\n"
        "loghub_ssh,E1,2,x <*> y [[<*>]],\n"
        "loghub_ssh,E1,literal,x <*> y <*>, root ; admin\n",
        encoding="utf-8",
    )
    got = read_sheet(p)["loghub_ssh"]["E1"]
    assert got == {"slots": ["USER", None], "literal_users": ["admin", "root"]}
    p.write_text("corpus,template_id,slot,template,label\nloghub_ssh,E1,1,t,PORT\n", "utf-8")
    with pytest.raises(ValueError):
        read_sheet(p)
