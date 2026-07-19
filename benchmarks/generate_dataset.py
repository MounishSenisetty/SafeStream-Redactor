"""Generate a synthetic labeled PII dataset for benchmarking.

Writes two files:

* ``dataset.txt``   — the corpus
* ``dataset.json``  — ground-truth spans: [{"start", "end", "type", "text"}, ...]

Usage::

    python benchmarks/generate_dataset.py --size-mb 10 --out benchmarks/data
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

FIRST = ["James", "Maria", "Wei", "Aisha", "Carlos", "Yuki", "Priya", "Liam", "Fatima", "Igor"]
LAST = ["Smith", "Garcia", "Chen", "Okafor", "Patel", "Kowalski", "Tanaka", "Brown", "Ali", "Novak"]
DOMAINS = ["corpmail.com", "workplace.io", "bizmail.net", "companyhq.org"]
FILLER = (
    "The quarterly report was filed on time. Please review the attached documents "
    "and respond by end of week. The deployment pipeline completed successfully. "
    "Meeting notes have been distributed to all stakeholders for further review. "
)


def luhn_complete(prefix15: str) -> str:
    digits = [int(c) for c in prefix15]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:  # positions relative to the (appended) check digit
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix15 + str((10 - total % 10) % 10)


def make_entity(rng: random.Random) -> tuple[str, str]:
    """Return (entity_type, text)."""
    kind = rng.choice(["email", "phone", "credit_card", "ssn", "ipv4"])
    if kind == "email":
        return kind, (
            f"{rng.choice(FIRST).lower()}.{rng.choice(LAST).lower()}"
            f"{rng.randint(1, 99)}@{rng.choice(DOMAINS)}"
        )
    if kind == "phone":
        return kind, (
            f"+{rng.randint(1, 99)} {rng.randint(200, 999)} "
            f"{rng.randint(100, 999)} {rng.randint(1000, 9999)}"
        )
    if kind == "credit_card":
        prefix = "4" + "".join(str(rng.randint(0, 9)) for _ in range(14))
        n = luhn_complete(prefix)
        return kind, f"{n[:4]} {n[4:8]} {n[8:12]} {n[12:]}"
    if kind == "ssn":
        return kind, f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
    return (
        "ipv4",
        f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
    )


CONTEXT = {
    "email": "contact email: {}",
    "phone": "phone {}",
    "credit_card": "card number {}",
    "ssn": "ssn: {}",
    "ipv4": "server ip {}",
}


def generate(size_mb: float, out_dir: Path, seed: int = 42) -> None:
    rng = random.Random(seed)
    target = int(size_mb * 1024 * 1024)
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: list[dict] = []
    pos = 0
    parts: list[str] = []
    while pos < target:
        filler = FILLER[: rng.randint(60, len(FILLER))] + "\n"
        parts.append(filler)
        pos += len(filler)
        kind, text = make_entity(rng)
        sentence = CONTEXT[kind].format(text) + ". "
        start = pos + sentence.index(text)
        labels.append({"start": start, "end": start + len(text), "type": kind, "text": text})
        parts.append(sentence)
        pos += len(sentence)
    (out_dir / "dataset.txt").write_text("".join(parts), encoding="utf-8")
    (out_dir / "dataset.json").write_text(json.dumps(labels), encoding="utf-8")
    print(f"wrote {pos / 1e6:.1f} MB corpus with {len(labels)} labeled entities to {out_dir}/")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--size-mb", type=float, default=10.0)
    ap.add_argument("--out", type=Path, default=Path(__file__).parent / "data")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    generate(args.size_mb, args.out, args.seed)
