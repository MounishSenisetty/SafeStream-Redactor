"""Evaluation corpora behind one interface, with fixed dev/test splits.

Every loader returns ``list[Doc]`` in a stable order. Gold labels are mapped onto
one canonical vocabulary -- Presidio's entity names, folded the way
presidio-research's own evaluator folds them (street addresses and GPEs are
``LOCATION``; identity numbers other than US SSNs are ``ID``; credentials are
``SECRET``). A label with no mapping keeps its own name, so no gold type is ever
dropped from scoring.

Third-party data is never committed. Each external corpus is downloaded once into
``benchmarks/data/external/<name>/`` (gitignored) at a pinned revision, recorded in a
``REVISION`` file; the split manifest under ``splits/`` pins the SHA-256 of the
source so a changed download is refused rather than silently scored.

=================  ===========================  =====================================
corpus             source / licence             notes
=================  ===========================  =====================================
redactionbench     vendored (HF, see its card)  tuned on before 2026-10-03: its test
                                                half is reported "previously exposed"
presidio_research  presidio-research, MIT       ``data/synth_dataset_v2.json``
ai4privacy         pii-masking-300k, academic   English validation file; non-commercial
                   use only (LICENSE.md)        research use, acknowledge AI4Privacy
conll2003          tner/conll2003, Reuters      test split; ``dslim/distilbert-NER`` is
                                                trained on CoNLL train, so not counted
                                                as independent for the ONNX tier
n2c2               i2b2/n2c2 2014, DUA          loader only (``N2C2_DIR`` env var)
secrets            Nosey Parker rules,          rule ``examples`` (positives) and
                   Apache-2.0                   generated hard negatives (UUIDs,
                                                hashes, base64, minified JS)
logs               generate_hard_dataset.py     self-generated regression fixture, not
                                                an accuracy corpus
=================  ===========================  =====================================
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import random
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = ROOT / "benchmarks" / "data" / "external"
SPLITS = Path(__file__).resolve().parent / "splits"


@dataclass(frozen=True, slots=True)
class Gold:
    start: int
    end: int
    type: str
    necessity: str | None = None  # "mandatory" / "contextual" where the corpus says so


@dataclass(slots=True)
class Doc:
    doc_id: str
    text: str
    spans: list[Gold] = field(default_factory=list)


@dataclass(slots=True)
class Corpus:
    name: str
    docs: list[Doc]
    sources: list[Path]  # files hashed into the split manifest
    revision: str | None = None
    notes: str = ""
    skipped: list[str] = field(default_factory=list)  # gold the loader could not place


def _revision(directory: Path) -> str | None:
    rev = directory / "REVISION"
    return rev.read_text(encoding="utf-8").strip() if rev.exists() else None


def _require(path: Path, how: str) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; {how}")
    return path


# --- canonical vocabulary ------------------------------------------------------

# SafeStream EntityType value -> canonical. Credentials all become SECRET.
SAFESTREAM_TO_CANONICAL: dict[str, str] = {
    "person": "PERSON",
    "org": "ORGANIZATION",
    "loc": "LOCATION",
    "address": "LOCATION",
    "email": "EMAIL_ADDRESS",
    "phone": "PHONE_NUMBER",
    "credit_card": "CREDIT_CARD",
    "ssn": "US_SSN",
    "ipv4": "IP_ADDRESS",
    "ipv6": "IP_ADDRESS",
    "date": "DATE_TIME",
    "dob": "DATE_TIME",
    "iban": "IBAN_CODE",
    "crypto_address": "CRYPTO",
    "mac_address": "MAC_ADDRESS",
    "id_number": "ID",
    "aws_account_id": "ID",
    "in_aadhaar": "ID",
    "in_pan": "ID",
    "nhs_number": "ID",
    "uk_nino": "ID",
    "custom": "CUSTOM",
    "username": "USERNAME",
    "url": "URL",
    "sex": "SEX",
    "title": "TITLE",
    "nrp": "NRP",
}
_SECRET_TYPES = [
    "anthropic_key",
    "api_key",
    "aws_key",
    "aws_secret",
    "github_token",
    "google_api_key",
    "jwt",
    "npm_token",
    "openai_key",
    "private_key",
    "secret",
    "sendgrid_key",
    "slack_token",
    "slack_webhook",
    "stripe_key",
    "twilio_key",
    "url_credentials",
    "vendor_token",
    "password_hash",
]
SAFESTREAM_TO_CANONICAL.update(dict.fromkeys(_SECRET_TYPES, "SECRET"))

# Presidio entity -> canonical: identity, except identity numbers fold into ID.
_PRESIDIO_ID = [
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_BANK_NUMBER",
    "MEDICAL_LICENSE",
    "UK_NHS",
    "UK_NINO",
    "IN_PAN",
    "IN_AADHAAR",
    "IN_PASSPORT",
    "IN_VOTER",
    "IN_VEHICLE_REGISTRATION",
    "AU_ABN",
    "AU_ACN",
    "AU_TFN",
    "AU_MEDICARE",
    "SG_NRIC_FIN",
    "SG_UEN",
    "ES_NIF",
    "ES_NIE",
    "IT_FISCAL_CODE",
    "IT_DRIVER_LICENSE",
    "IT_VAT_CODE",
    "IT_PASSPORT",
    "IT_IDENTITY_CARD",
    "PL_PESEL",
    "FI_PERSONAL_IDENTITY_CODE",
]


# Canonical types Presidio (its recognizers + its spaCy/transformers NER) can
# emit. "Presidio-scope" metrics score only gold of these types, so adding a type
# Presidio lacks (SECRET, USERNAME, MAC_ADDRESS, ...) can never raise them. Types
# only Presidio detects (URL, NRP, ...) stay in scope: a stricter test for
# SafeStream than "types both tools detect".
PRESIDIO_SCOPE = frozenset(
    {
        "PERSON",
        "LOCATION",
        "ORGANIZATION",
        "NRP",
        "DATE_TIME",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "US_SSN",
        "IP_ADDRESS",
        "IBAN_CODE",
        "URL",
        "CRYPTO",
        "ID",
    }
)


def presidio_to_canonical(entity: str) -> str:
    return "ID" if entity in _PRESIDIO_ID else entity


# --- loaders -------------------------------------------------------------------


def load_redactionbench() -> Corpus:
    from benchmarks.redactionbench import loader

    directory = ROOT / "benchmarks" / "data" / "redactionbench"
    res = loader.load_from_directory(directory, loader.FieldSpec())
    docs = [
        Doc(r.doc_id, r.text, [Gold(s.start, s.end, "SENSITIVE", s.label) for s in r.spans])
        for r in res.records
    ]
    return Corpus(
        "redactionbench",
        docs,
        [Path(f) if Path(f).is_absolute() else ROOT / f for f in res.files],
        _revision(directory),
        "binary redaction gold (necessity only, no PII types); tuned on before the split",
    )


_PRESIDIO_RESEARCH_MAP = {"STREET_ADDRESS": "LOCATION", "GPE": "LOCATION", "ZIP_CODE": "LOCATION"}
_PRESIDIO_RESEARCH_MAP |= {"DOMAIN_NAME": "URL", "US_DRIVER_LICENSE": "ID"}


def load_presidio_research() -> Corpus:
    directory = EXTERNAL / "presidio_research"
    path = _require(directory / "synth_dataset_v2.json", "see benchmarks/corpora/README.md")
    data = json.loads(path.read_text(encoding="utf-8"))
    docs = []
    for i, obj in enumerate(data):
        spans = [
            Gold(
                s["start_position"],
                s["end_position"],
                _PRESIDIO_RESEARCH_MAP.get(s["entity_type"], s["entity_type"]),
            )
            for s in obj["spans"]
        ]
        docs.append(Doc(f"pr-{i:04d}", obj["full_text"], spans))
    return Corpus("presidio_research", docs, [path], _revision(directory))


_AI4PRIVACY_MAP = {
    **dict.fromkeys(["GIVENNAME1", "GIVENNAME2", "LASTNAME1", "LASTNAME2", "LASTNAME3"], "PERSON"),
    **dict.fromkeys(
        ["CITY", "STATE", "COUNTRY", "STREET", "BUILDING", "SECADDRESS", "POSTCODE", "GEOCOORD"],
        "LOCATION",
    ),
    **dict.fromkeys(["DATE", "TIME", "BOD"], "DATE_TIME"),
    **dict.fromkeys(["SOCIALNUMBER", "IDCARD", "PASSPORT", "DRIVERLICENSE"], "ID"),
    "EMAIL": "EMAIL_ADDRESS",
    "TEL": "PHONE_NUMBER",
    "IP": "IP_ADDRESS",
    "PASS": "SECRET",
}


def load_ai4privacy() -> Corpus:
    directory = EXTERNAL / "ai4privacy_300k"
    path = _require(directory / "1english_openpii_8k.jsonl", "see benchmarks/corpora/README.md")
    docs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        raw = obj["privacy_mask"]
        masks = ast.literal_eval(raw) if isinstance(raw, str) else raw
        spans = [
            Gold(m["start"], m["end"], _AI4PRIVACY_MAP.get(m["label"], m["label"])) for m in masks
        ]
        docs.append(Doc(f"a4p-{obj['id']}", obj["source_text"], spans))
    return Corpus(
        "ai4privacy",
        docs,
        [path],
        _revision(directory),
        "AI4Privacy pii-masking-300k, academic non-commercial licence; acknowledge AI4Privacy",
    )


_CONLL_MAP = {"PER": "PERSON", "ORG": "ORGANIZATION", "LOC": "LOCATION"}  # MISC stays MISC
_CONLL_SENTENCES_PER_DOC = 10


def load_conll2003() -> Corpus:
    directory = EXTERNAL / "conll2003"
    path = _require(directory / "test.json", "see benchmarks/corpora/README.md")
    id2label = {v: k for k, v in json.loads((directory / "label.json").read_text()).items()}
    sentences = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    docs = []
    for d in range(0, len(sentences), _CONLL_SENTENCES_PER_DOC):
        text, spans = "", []
        for sent in sentences[d : d + _CONLL_SENTENCES_PER_DOC]:
            if text:
                text += "\n"
            cur: list = []  # [start, end, type] of the open entity
            for token, tag_id in zip(sent["tokens"], sent["tags"], strict=True):
                if text and not text.endswith("\n"):
                    text += " "
                start = len(text)
                text += token
                prefix, _, etype = id2label[tag_id].partition("-")
                if prefix == "B" or (prefix == "I" and (not cur or cur[2] != etype)):
                    if cur:
                        spans.append(cur)
                    cur = [start, len(text), etype]
                elif prefix == "I":
                    cur[1] = len(text)
                elif cur:
                    spans.append(cur)
                    cur = []
            if cur:
                spans.append(cur)
        docs.append(
            Doc(
                f"conll-{d // _CONLL_SENTENCES_PER_DOC:04d}",
                text,
                [Gold(s, e, _CONLL_MAP.get(t, t)) for s, e, t in spans],
            )
        )
    return Corpus(
        "conll2003",
        docs,
        [path],
        _revision(directory),
        "CoNLL-2003 test; the bundled ONNX model was trained on CoNLL train",
    )


def load_n2c2() -> Corpus:
    """i2b2/n2c2 2014 de-identification XML (``<TEXT>`` + ``<TAGS>``), from ``$N2C2_DIR``.

    Requires a data use agreement, so nothing is downloaded or committed; the
    split manifest is generated locally by whoever holds the data.
    """
    import xml.etree.ElementTree as ET

    directory = Path(os.environ.get("N2C2_DIR", EXTERNAL / "n2c2"))
    files = sorted(_require(directory, "set N2C2_DIR to the i2b2 2014 XML folder").glob("*.xml"))
    n2c2_map = {"NAME": "PERSON", "LOCATION": "LOCATION", "DATE": "DATE_TIME", "AGE": "AGE"}
    n2c2_map |= {"CONTACT": "PHONE_NUMBER", "ID": "ID", "PROFESSION": "PROFESSION"}
    docs = []
    for f in files:
        root = ET.parse(f).getroot()
        text = root.findtext("TEXT") or ""
        spans = [
            Gold(int(t.get("start", 0)), int(t.get("end", 0)), n2c2_map.get(t.tag, t.tag))
            for t in (root.find("TAGS") or [])
        ]
        docs.append(Doc(f"n2c2-{f.stem}", text, spans))
    return Corpus("n2c2", docs, files, None, "DUA-restricted; local only")


_NP_RULES = "crates/noseyparker/data/default/builtin/rules"


def _np_regex(pattern: str) -> re.Pattern[str]:
    # Nosey Parker patterns are Rust regex in (?x) verbose mode; Python accepts them
    # once Rust-only inline flags are dropped.
    return re.compile(pattern.replace("(?-u)", ""), re.VERBOSE)


def load_secrets() -> Corpus:
    """Nosey Parker rule examples as positives; generated hard negatives (UUIDs,
    hashes, base64 blobs, minified JS) as secret-free docs.

    Gold is the rule's own capture group(s) -- Nosey Parker's labelling, not ours --
    or the whole match for a rule without groups. An example its own rule cannot
    place (a Rust-only regex construct) is listed in ``skipped``, never dropped
    silently.
    """
    import yaml

    directory = EXTERNAL / "noseyparker"
    rules_dir = _require(directory / _NP_RULES, "see benchmarks/corpora/README.md")
    files = sorted(rules_dir.glob("*.yml"))
    docs: list[Doc] = []
    skipped: list[str] = []
    for f in files:
        for rule in yaml.safe_load(f.read_text(encoding="utf-8")).get("rules", []):
            rid = rule.get("id", rule.get("name", f.stem))
            try:
                rx = _np_regex(rule["pattern"])
            except re.error as exc:
                skipped.append(f"{rid}: pattern does not compile in Python ({exc})")
                continue
            for k, example in enumerate(rule.get("examples") or []):
                m = rx.search(example)
                if m is None:
                    skipped.append(f"{rid}#{k}: rule does not match its own example")
                    continue
                groups = [g for g in range(1, (m.re.groups or 0) + 1) if m.start(g) >= 0]
                places = [(m.start(g), m.end(g)) for g in groups] or [(m.start(), m.end())]
                spans = [Gold(s, e, "SECRET") for s, e in places if e > s]
                docs.append(Doc(f"np-pos-{rid}-{k}", example, spans))
            # Nosey Parker's negative_examples are NOT used: they mean "this rule
            # must not fire", not "nothing sensitive here" -- many hold real emails,
            # IPs or secret-shaped values that a redactor is right to hide.
    docs.extend(_hard_negatives())
    return Corpus(
        "secrets",
        docs,
        files,
        _revision(directory),
        "positives: Nosey Parker rule examples (Apache-2.0); negatives: generated "
        "high-entropy non-secrets (UUIDs, commit SHAs, digests, base64 images, minified JS)",
        skipped,
    )


def _hard_negatives(n: int = 200, seed: int = 20261003) -> list[Doc]:
    """High-entropy text that is *not* a secret: what a secret scanner must not flag."""
    rng = random.Random(seed)

    def rbytes(k: int) -> bytes:
        return bytes(rng.randrange(256) for _ in range(k))

    makers: list[tuple[str, Callable[[], str]]] = [
        ("uuid", lambda: f"request_id={uuid.UUID(bytes=rbytes(16), version=4)} status=200"),
        ("sha1", lambda: f"commit {hashlib.sha1(rbytes(32)).hexdigest()} Merge branch 'main'"),
        ("sha256", lambda: f"sha256:{hashlib.sha256(rbytes(32)).hexdigest()}  image.tar"),
        (
            "png",
            lambda: (
                '<img src="data:image/png;base64,'
                + base64.b64encode(b"\x89PNG\r\n\x1a\n" + rbytes(180)).decode()
                + '">'
            ),
        ),
        (
            "minjs",
            lambda: (
                "!function(e,t){var n="
                + ",".join(f"{rng.choice('abcdefghijklmnopqrstuvwxyz')}{i}" for i in range(40))
                + ';return e.exports=t(n)}(this,function(r){"use strict";return r});'
            ),
        ),
    ]
    return [
        Doc(f"neg-{name}-{i:03d}", make(), [])
        for name, make in makers
        for i in range(n // len(makers))
    ]


def load_logs() -> Corpus:
    directory = ROOT / "benchmarks" / "data_hard"
    text_path = _require(
        directory / "dataset.txt", "run: python benchmarks/generate_hard_dataset.py --size-mb 1"
    )
    gold = json.loads((directory / "dataset.json").read_text())
    gold = gold["entities"] if isinstance(gold, dict) else gold
    to_canon = {"email": "EMAIL_ADDRESS", "phone": "PHONE_NUMBER", "credit_card": "CREDIT_CARD"}
    to_canon |= {"ssn": "US_SSN", "ipv4": "IP_ADDRESS"}
    text = text_path.read_text(encoding="utf-8")
    # one doc per 64 KiB line-aligned block so the split and bootstrap have units
    docs, start, i = [], 0, 0
    while start < len(text):
        end = text.find("\n", start + 65536)
        end = len(text) if end < 0 else end + 1
        spans = [
            Gold(g["start"] - start, g["end"] - start, to_canon.get(g["type"], g["type"]))
            for g in gold
            if start <= g["start"] < end
        ]
        docs.append(Doc(f"logs-{i:04d}", text[start:end], spans))
        start, i = end, i + 1
    return Corpus("logs", docs, [text_path], None, "self-generated regression fixture")


LOADERS: dict[str, Callable[[], Corpus]] = {
    "redactionbench": load_redactionbench,
    "presidio_research": load_presidio_research,
    "ai4privacy": load_ai4privacy,
    "conll2003": load_conll2003,
    "n2c2": load_n2c2,
    "secrets": load_secrets,
    "logs": load_logs,
}


def source_sha256(corpus: Corpus) -> str:
    h = hashlib.sha256()
    for p in sorted(corpus.sources):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def load(name: str, split: str = "all") -> Corpus:
    """Load ``name`` restricted to ``split`` ('dev', 'test' or 'all').

    'dev'/'test' need the committed manifest and refuse a source whose hash no
    longer matches it: tuning on one version and testing on another is a leak.
    """
    if name not in LOADERS:
        raise KeyError(f"unknown corpus {name!r}; choose from {sorted(LOADERS)}")
    corpus = LOADERS[name]()
    # a span past the end of its text is a source data error: clip it, and say so
    for d in corpus.docs:
        for i, s in enumerate(d.spans):
            if s.start < 0 or s.end > len(d.text):
                d.spans[i] = Gold(max(0, s.start), min(len(d.text), s.end), s.type, s.necessity)
                corpus.skipped.append(f"{d.doc_id}: span {s.start}-{s.end} clipped to text")
        d.spans = [s for s in d.spans if s.end > s.start]
    if split == "all":
        return corpus
    manifest_path = SPLITS / f"{name}.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"no split manifest for {name}; run benchmarks/corpora/split.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["source_sha256"] != source_sha256(corpus):
        raise ValueError(f"{name}: source changed since the split manifest was written")
    keep = set(manifest[split])
    corpus.docs = [d for d in corpus.docs if d.doc_id in keep]
    return corpus
