from benchmarks.corpora import Doc, Gold
from benchmarks.leak_analysis import analyse


def test_partial_and_missed_spans_are_counted_separately() -> None:
    doc = Doc(
        "d",
        "Alice met bob at 555-1234",
        [
            Gold(0, 5, "SENSITIVE", "mandatory"),
            Gold(10, 13, "SENSITIVE", "mandatory"),
            Gold(17, 25, "SENSITIVE", "mandatory"),
        ],
    )
    clean = Doc("c", "x 1", [Gold(2, 3, "SENSITIVE", "mandatory")])
    r = analyse([doc, clean], [[[0, 5, "PERSON"], [17, 20, "PHONE"]], [[2, 3, "ID"]]])
    assert r["spans"] == {"total": 4, "fully_redacted": 2, "partially_redacted": 1, "missed": 1}
    assert r["leaked_chars"]["from_partial_spans"] == 5
    assert r["leaked_chars"]["from_missed_spans"] == 3
    assert r["no_leak_docs"] == 1
    assert r["docs_leaking_le"][2] == 2
