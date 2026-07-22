"""Generate a *realistic, adversarial* labeled dataset for benchmarking.

Unlike ``generate_dataset.py`` (clean sentences, entity formats hand-picked to
match the detectors), this generator embeds real PII inside noisy log / JSON /
CSV / SQL records that are dense with **hard negatives** — tokens engineered to
tempt a naive pattern matcher into false positives:

* 16-digit order numbers that fail the Luhn checksum (not credit cards)
* 5-octet dotted numbers and version strings (not IPv4)
* 9-digit ids with no SSN context, and invalid-area SSNs (000/666/9xx)
* UUIDs, git commit hashes, ISO timestamps, tracking numbers

Only genuine PII is written to the gold file, so the benchmark measures
**precision** (false positives on the distractors) as well as recall — a
meaningfully harder and less circular test than the clean corpus.

Usage::

    python benchmarks/generate_hard_dataset.py --size-mb 5 --out benchmarks/data_hard
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

FIRST = ["james", "maria", "wei", "aisha", "carlos", "yuki", "priya", "liam", "fatima", "igor"]
LAST = ["smith", "garcia", "chen", "okafor", "patel", "kowalski", "tanaka", "brown", "ali", "roy"]
DOMAINS = ["corpmail.com", "workplace.io", "bizmail.net", "companyhq.org"]


def luhn_complete(prefix15: str) -> str:
    digits = [int(c) for c in prefix15]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix15 + str((10 - total % 10) % 10)


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# --- generators for genuine PII (gold) -------------------------------------


def gen_email(rng):
    return f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randint(1, 99)}@{rng.choice(DOMAINS)}"


def gen_phone(rng):
    return (
        f"+{rng.randint(1, 60)} {rng.randint(200, 999)} "
        f"{rng.randint(100, 999)} {rng.randint(1000, 9999)}"
    )


def gen_card(rng):
    return luhn_complete("4" + "".join(str(rng.randint(0, 9)) for _ in range(14)))


def gen_ssn(rng):
    return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


def gen_ipv4(rng):
    return (
        f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    )


# --- hard negatives (must NOT be labeled or detected) ----------------------


def neg_order(rng):
    # 16 digits that FAIL Luhn -> an order id, not a card
    while True:
        n = "".join(str(rng.randint(0, 9)) for _ in range(16))
        if not luhn_ok(n):
            return n


def neg_five_octets(rng):
    return ".".join(str(rng.randint(1, 255)) for _ in range(5))  # not an IPv4


def neg_bare9(rng):
    return "".join(str(rng.randint(0, 9)) for _ in range(9))  # 9 digits, no SSN context


def neg_bad_ssn(rng):
    area = rng.choice(["000", "666", f"9{rng.randint(0, 9)}{rng.randint(0, 9)}"])
    return f"{area}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"  # invalid area


def neg_uuid(rng):
    h = "0123456789abcdef"
    p = lambda k: "".join(rng.choice(h) for _ in range(k))  # noqa: E731
    return f"{p(8)}-{p(4)}-{p(4)}-{p(4)}-{p(12)}"


def neg_githash(rng):
    return "".join(rng.choice("0123456789abcdef") for _ in range(40))


def neg_timestamp(rng):
    return f"2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"


def neg_tracking(rng):
    return "1Z" + "".join(rng.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(16))


NEGS = [
    neg_order,
    neg_five_octets,
    neg_bare9,
    neg_bad_ssn,
    neg_uuid,
    neg_githash,
    neg_timestamp,
    neg_tracking,
]


# --- record templates ------------------------------------------------------
# Each returns (text, spans) where spans is a list of (local_start, local_end, type).


def rec_log(rng):
    email, ip = gen_email(rng), gen_ipv4(rng)
    text = (
        f"{neg_timestamp(rng)} INFO user={email} src_ip={ip} "
        f"req={neg_githash(rng)} order={neg_order(rng)} status=200\n"
    )
    spans = [
        (text.index(email), text.index(email) + len(email), "email"),
        (text.index(f"src_ip={ip}") + 7, text.index(f"src_ip={ip}") + 7 + len(ip), "ipv4"),
    ]
    return text, spans


def rec_csv(rng):
    name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
    phone, ssn = gen_phone(rng), gen_ssn(rng)
    text = f"{rng.randint(1, 9999)},{name},{phone},{ssn},ref-{neg_bare9(rng)}\n"
    spans = [
        (text.index(phone), text.index(phone) + len(phone), "phone"),
        (text.index(ssn), text.index(ssn) + len(ssn), "ssn"),
    ]
    return text, spans


def rec_sql(rng):
    card = gen_card(rng)
    text = (
        f"INSERT INTO tx (pan, note, ver) VALUES "
        f"('{card}', '{neg_bad_ssn(rng)}', 'v{neg_five_octets(rng)}');\n"
    )
    spans = [(text.index(card), text.index(card) + len(card), "credit_card")]
    return text, spans


def rec_json(rng):
    email = gen_email(rng)
    text = (
        f'{{"contact": "{email}", "uuid": "{neg_uuid(rng)}", '
        f'"track": "{neg_tracking(rng)}", "n": {neg_order(rng)}}}\n'
    )
    spans = [(text.index(email), text.index(email) + len(email), "email")]
    return text, spans


TEMPLATES = [rec_log, rec_csv, rec_sql, rec_json]


def generate(size_mb: float, out_dir: Path, seed: int = 7) -> None:
    rng = random.Random(seed)
    target = int(size_mb * 1024 * 1024)
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: list[dict] = []
    parts: list[str] = []
    pos = 0
    while pos < target:
        text, spans = rng.choice(TEMPLATES)(rng)
        for ls, le, kind in spans:
            labels.append({"start": pos + ls, "end": pos + le, "type": kind, "text": text[ls:le]})
        parts.append(text)
        pos += len(text)
    (out_dir / "dataset.txt").write_text("".join(parts), encoding="utf-8")
    (out_dir / "dataset.json").write_text(json.dumps(labels), encoding="utf-8")
    print(
        f"wrote {pos / 1e6:.1f} MB adversarial corpus with "
        f"{len(labels)} gold entities to {out_dir}/"
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size-mb", type=float, default=5.0)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "data_hard")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    generate(args.size_mb, args.out, args.seed)
