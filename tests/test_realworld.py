"""The real-world evaluation pipeline, on a tiny corpus of documented fake values."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from benchmarks import cluster_bootstrap, corpora
from benchmarks.corpora import split
from benchmarks.realworld import __main__ as cli
from benchmarks.realworld import agreement, data, labelstudio, score

# Documented fakes only: AWS's published example key, example.com, TEST-NET IPs.
KEY = "AKIAIOSFODNN7EXAMPLE"
DOCS = [
    ("ci-1", f"export AWS_ACCESS_KEY_ID={KEY}\nok", "repo-a", "ci-log"),
    ("ci-2", "deploy by jane.doe@example.com from 192.0.2.10", "repo-a", "ci-log"),
    ("app-1", "user=bob ip=198.51.100.7 status=200", "svc-b", "app-log"),
    ("app-2", "nothing sensitive in this line", "svc-b", "app-log"),
    ("cfg-1", f"aws_key: {KEY}", "host-c", "config"),
]


def _gold() -> dict[str, list[dict]]:
    t = {d[0]: d[1] for d in DOCS}

    def at(doc: str, value: str, typ: str, sub: str | None = None) -> dict:
        i = t[doc].index(value)
        s = {"start": i, "end": i + len(value), "type": typ}
        return s | ({"subtype": sub} if sub else {})

    return {
        "ci-1": [at("ci-1", KEY, "SECRET", "aws_key")],
        "ci-2": [
            at("ci-2", "jane.doe@example.com", "EMAIL_ADDRESS"),
            at("ci-2", "192.0.2.10", "IP_ADDRESS"),
        ],
        "app-1": [at("app-1", "198.51.100.7", "IP_ADDRESS")],
        "app-2": [],
        "cfg-1": [at("cfg-1", KEY, "SECRET", "aws_key")],
    }


def _write(path: Path, gold: dict[str, list[dict]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"doc_id": k, "spans": v}) + "\n" for k, v in gold.items()))


def make_corpus(root: Path, *, provenance: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if provenance:
        prov = {k: f"test {k}" for k in data.PROVENANCE_KEYS}
        (root / "provenance.json").write_text(json.dumps(prov))
    (root / "documents.jsonl").write_text(
        "".join(
            json.dumps({"doc_id": i, "text": t, "source": s, "kind": k}) + "\n"
            for i, t, s, k in DOCS
        )
    )
    gold = _gold()
    _write(root / "annotations" / "a.jsonl", gold)
    b = {k: list(v) for k, v in gold.items()}
    b["app-1"] = []  # annotator b missed the IP address
    _write(root / "annotations" / "b.jsonl", b)
    _write(root / "adjudicated.jsonl", gold)
    return root


@pytest.fixture
def corpus_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = make_corpus(tmp_path / "realworld")
    monkeypatch.setenv("SAFESTREAM_REALWORLD_DIR", str(root))
    monkeypatch.setattr(corpora, "SPLITS", tmp_path / "splits")
    return root


def test_clean_corpus_validates_and_summarises_without_text(corpus_dir: Path) -> None:
    ds = data.load_dataset()
    assert ds.issues == []
    s = data.summary(ds)
    assert s["n_docs"] == 5 and s["gold_free_docs"] == 1
    assert s["gold_types"] == {"SECRET": 2, "EMAIL_ADDRESS": 1, "IP_ADDRESS": 2}
    assert s["gold_subtypes"] == {"SECRET:aws_key": 2}
    assert KEY not in json.dumps(s)  # counts only, never document text


def test_validation_catches_each_defect(tmp_path: Path) -> None:
    root = make_corpus(tmp_path / "rw", provenance=False)
    bad = _gold()
    bad["ci-1"] = [{"start": 5, "end": 999, "type": "SECRET"}]
    bad["ci-2"] = [{"start": 0, "end": 3, "type": "PASSWORDISH"}]
    del bad["app-2"]
    _write(root / "adjudicated.jsonl", bad)
    issues = "\n".join(data.load_dataset(root).issues)
    assert "provenance.json is missing" in issues
    assert "outside" in issues and "not in the canonical set" in issues
    assert "no line for app-2" in issues
    with pytest.raises(ValueError, match="validation issues"):
        data.to_corpus(data.load_dataset(root))


def test_binary_kappa_matches_hand_computation() -> None:
    a = [data.Span(0, 4, "ID")]
    b = [data.Span(0, 2, "ID"), data.Span(8, 10, "ID")]
    c = agreement.doc_counts(a, b, 10)
    kappa = agreement.metrics(lambda k: c[k])["char_kappa_binary"]
    # both 2, A-only 2, B-only 2, neither 4: po .6, pe .52, kappa .08/.48
    assert kappa == pytest.approx(0.08 / 0.48)


def test_agreement_report(corpus_dir: Path) -> None:
    ds = data.load_dataset()
    labels = data.sources_of([d.doc_id for d in ds.documents])
    res = agreement.agreement(ds, labels, resamples=200)
    pair = res["pairs"]["a vs b"]
    assert pair["point"]["span_f1_exact"] == pytest.approx(2 * 4 / (5 + 4))
    assert pair["point"]["type_agreement_on_overlaps"] == 1.0
    assert 0 < pair["point"]["char_kappa_binary"] < 1
    assert pair["per_type"]["IP_ADDRESS"]["spans_b"] == 1
    lo, hi = pair["ci95"]["two_stage"]["char_kappa_binary"]
    assert lo <= pair["point"]["char_kappa_binary"] <= hi


def test_corpus_is_test_only_and_clusters_by_source(corpus_dir: Path) -> None:
    corpus = corpora.load("realworld")
    manifest = split.make_manifest(corpus)
    assert manifest["dev"] == [] and len(manifest["test"]) == 5
    assert manifest["test_only"]
    labels = cluster_bootstrap.clusters_for("realworld", corpus.docs)
    assert labels == [
        "source:repo-a",
        "source:repo-a",
        "source:svc-b",
        "source:svc-b",
        "source:host-c",
    ]


def _preds(miss: set[str]) -> list[list[list]]:
    gold = _gold()
    return [
        [[s["start"], s["end"], s["type"]] for s in gold[d[0]] if s["type"] not in miss]
        for d in DOCS
    ]


def test_scores_per_type_and_leaks(corpus_dir: Path) -> None:
    ds = data.load_dataset()
    labels = data.sources_of([d.doc_id for d in ds.documents])
    preds = {"all": _preds(set()), "nosecret": _preds({"SECRET"})}
    res = score.score(ds, preds, [("all", "nosecret")], labels, resamples=200)
    assert res["point"]["all"]["entity_recall_covered"] == 1.0
    assert res["point"]["nosecret"]["entity_recall_covered"] == pytest.approx(3 / 5)
    assert res["per_type"]["nosecret"]["SECRET:aws_key"]["fully_redacted"] == 0.0
    assert res["per_type"]["nosecret"]["IP_ADDRESS"]["fully_redacted"] == 1.0
    assert res["leaks"]["all"]["_credential_leaks"] == 0
    assert res["leaks"]["nosecret"]["_credential_leaks"] == 2
    assert res["leaks"]["nosecret"]["SECRET"]["docs"] == ["cfg-1", "ci-1"]
    names = {"all": "Oracle", "nosecret": "No secrets"}
    assert r"\pc{1.000}" in score.latex_main(res, names)
    assert "SECRET:aws\\_key" in score.latex_types(res, names)
    # five documents: some resamples hold neither secret document, so the FR
    # difference's interval reaches zero and is marked as not significant
    fr_row = score.latex_pairs(res, names).split("\n")[4]
    assert fr_row.startswith("Oracle $-$ No secrets & FR") and r"\ns" in fr_row


def test_labelstudio_export_converts(tmp_path: Path) -> None:
    text = DOCS[0][1]
    i = text.index(KEY)
    export = [
        {
            "id": 7,
            "data": {"text": text, "source": "repo-a"},
            "annotations": [
                {
                    "completed_by": {"id": 3, "email": "annotator@example.com"},
                    "result": [
                        {
                            "type": "labels",
                            "value": {"start": i, "end": i + len(KEY), "labels": ["AWS key"]},
                        }
                    ],
                }
            ],
        }
    ]
    out = tmp_path / "ls"
    counts = labelstudio.convert(export, out, {"AWS key": "SECRET:aws_key"})
    assert counts == {"documents": 1, "annotators": 1}
    line = json.loads((out / "annotations" / "annotator-3.jsonl").read_text())
    assert line == {
        "doc_id": "ls-7",
        "spans": [{"start": i, "end": i + len(KEY), "type": "SECRET", "subtype": "aws_key"}],
    }
    assert "example.com" not in (out / "annotations" / "annotator-3.jsonl").read_text()


def test_cli_end_to_end(corpus_dir: Path, tmp_path: Path) -> None:
    assert cli.main(["validate"]) == 0
    assert cli.main(["agreement", "--resamples", "50", "--json", str(tmp_path / "agr.json")]) == 0
    corpus = corpora.load("realworld")
    corpora.SPLITS.mkdir(parents=True)
    (corpora.SPLITS / "realworld.json").write_text(json.dumps(split.make_manifest(corpus)))
    ckpt = tmp_path / "ck.json"
    ckpt.write_text(json.dumps({"commit": "abc", "run": {"preds": _preds({"SECRET"})}}))
    out = tmp_path / "scores.json"
    argv = ["score", "--system", f"sys={ckpt}", "--resamples", "50", "--json", str(out)]
    assert cli.main([*argv, "--latex-dir", str(tmp_path / "tex")]) == 0
    res = json.loads(out.read_text())
    assert res["leaks"]["sys"]["_credential_leaks"] == 2
    assert KEY not in out.read_text()
    assert (tmp_path / "tex" / "tab_realworld_main.tex").exists()
