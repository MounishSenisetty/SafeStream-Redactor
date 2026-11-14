"""AgentTrace: synthetic tool outputs an LLM coding agent reads, with planted values.

Stack traces, ``.env``/YAML config, CI logs, ``git log``/``git diff`` excerpts, HTTP
dumps and support-ticket prose, each with planted personal data and credentials at
recorded offsets. Deterministic for a seed.

This corpus is **plumbing only** (egress, residual exposure, latency, policy cost):
the planted formats come from the same authors as the detection rules, so it must
never back a detection-accuracy claim.

    python -m benchmarks.generate_agent_traces --n 2000 --out traces.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import string
from collections.abc import Callable
from pathlib import Path

SEED = 20261114
FIRST = ["Maria", "James", "Aisha", "Wei", "Olga", "Rahul", "Fatima", "Diego", "Hannah", "Kenji"]
LAST = ["Gonzalez", "Okafor", "Lindqvist", "Nakamura", "Petrov", "Sharma", "Haddad", "Moreau"]
DOMAINS = ["corpmail.com", "example.org", "acme-labs.io", "northwind.net"]
B62 = string.ascii_letters + string.digits

Planted = tuple[str, str]  # (canonical type, value)


def _luhn(digits: str) -> str:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 == 0 else 1)
        total += n - 9 if n > 9 else n
    return digits + str((10 - total % 10) % 10)


def _values(rng: random.Random) -> dict[str, Callable[[], Planted]]:
    def name() -> Planted:
        return "PERSON", f"{rng.choice(FIRST)} {rng.choice(LAST)}"

    def email() -> Planted:
        local = f"{rng.choice(FIRST).lower()}.{rng.choice(LAST).lower()}"
        return "EMAIL_ADDRESS", f"{local}@{rng.choice(DOMAINS)}"

    def phone() -> Planted:
        return "PHONE_NUMBER", f"+1 ({rng.randint(201, 989)}) {rng.randint(200, 999)}-" + (
            f"{rng.randint(0, 9999):04d}"
        )

    def ipv4() -> Planted:
        return "IP_ADDRESS", ".".join(str(rng.randint(11, 223)) for _ in range(4))

    def aws() -> Planted:
        return "SECRET", "AKIA" + "".join(
            rng.choice(string.ascii_uppercase + "234567") for _ in range(16)
        )

    def github() -> Planted:
        return "SECRET", "ghp_" + "".join(rng.choice(B62) for _ in range(36))

    def stripe() -> Planted:
        return "SECRET", "sk_live_" + "".join(rng.choice(B62) for _ in range(24))

    def jwt() -> Planted:
        part = lambda n: "".join(rng.choice(B62 + "-_") for _ in range(n))  # noqa: E731
        return "SECRET", f"eyJhbGciOiJIUzI1NiJ9.{part(40)}.{part(43)}"

    def card() -> Planted:
        return "CREDIT_CARD", _luhn("4" + "".join(str(rng.randint(0, 9)) for _ in range(14)))

    def ssn() -> Planted:
        return "US_SSN", f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"

    return {
        "name": name, "email": email, "phone": phone, "ipv4": ipv4, "aws": aws,
        "github": github, "stripe": stripe, "jwt": jwt, "card": card, "ssn": ssn,
    }  # fmt: skip


# Each template is a list of literal pieces and {slot} markers naming a value kind.
TEMPLATES: dict[str, list[str]] = {
    "stack_trace": [
        "Traceback (most recent call last):\n"
        '  File "/srv/app/billing/charge.py", line 88, in charge\n'
        "    resp = client.post(url, json=payload)\n"
        "requests.exceptions.HTTPError: 402 for customer {email} card {card}\n"
        "  context: user={name} ip={ipv4} api_key={stripe}\n",
    ],
    "env_file": [
        "# .env (do not commit)\nDATABASE_URL=postgres://app@db.internal:5432/app\n"
        "AWS_ACCESS_KEY_ID={aws}\nGITHUB_TOKEN={github}\nSUPPORT_EMAIL={email}\n"
        "ADMIN_PHONE={phone}\n",
    ],
    "yaml_config": [
        "service:\n  name: payments\n  owner: {name}\n  contact: {email}\nauth:\n"
        "  jwt: {jwt}\n  allow_from: [{ipv4}]\n",
    ],
    "ci_log": [
        "2026-11-14T08:12:01Z [build] Step 4/9: RUN ./deploy.sh\n"
        "2026-11-14T08:12:03Z [deploy] using token {github}\n"
        "2026-11-14T08:12:04Z [deploy] notify {email} on failure\n"
        "2026-11-14T08:12:09Z [deploy] connected to {ipv4}:443\n",
    ],
    "git_log": [
        "commit 9f1c2e7a\nAuthor: {name} <{email}>\nDate:   Fri Nov 13 17:02:11 2026\n\n"
        "    Rotate leaked key {aws} and update contact {phone}\n",
    ],
    "git_diff": [
        "diff --git a/config/prod.py b/config/prod.py\n@@ -12,3 +12,3 @@\n"
        '-STRIPE_KEY = "{stripe}"\n+STRIPE_KEY = os.environ["STRIPE_KEY"]\n'
        " OWNER = '{name}'\n",
    ],
    "http_dump": [
        "POST /v1/users HTTP/1.1\nHost: api.internal\nAuthorization: Bearer {jwt}\n"
        "X-Forwarded-For: {ipv4}\n\n"
        '{{"name": "{name}", "email": "{email}", "ssn": "{ssn}", "phone": "{phone}"}}\n',
    ],
    "ticket": [
        "Ticket #4821 from {name} ({email}): I was charged twice on card {card}. "
        "Please call me at {phone}. My SSN on file is {ssn} if you need to verify.\n",
    ],
}


def generate(n: int, seed: int = SEED) -> list[dict[str, object]]:
    """``n`` documents: ``{"id", "kind", "text", "spans": [[start, end, type], ...]}``."""
    rng = random.Random(seed)
    makers = _values(rng)
    kinds = sorted(TEMPLATES)
    docs = []
    for i in range(n):
        kind = kinds[i % len(kinds)]
        template = rng.choice(TEMPLATES[kind])
        text, spans, pos = "", [], 0
        # walk the template, replacing {slot} (and keeping {{ }} as literal braces)
        while pos < len(template):
            if template.startswith("{{", pos) or template.startswith("}}", pos):
                text += template[pos]
                pos += 2
                continue
            if template[pos] == "{":
                end = template.index("}", pos)
                etype, value = makers[template[pos + 1 : end]]()
                spans.append([len(text), len(text) + len(value), etype])
                text += value
                pos = end + 1
                continue
            text += template[pos]
            pos += 1
        docs.append({"id": f"trace-{i:05d}", "kind": kind, "text": text, "spans": spans})
    return docs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with args.out.open("w", encoding="utf-8") as f:
        for d in generate(args.n, args.seed):
            f.write(json.dumps(d) + "\n")


if __name__ == "__main__":
    main()
