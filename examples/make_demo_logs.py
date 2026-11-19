#!/usr/bin/env python3
"""Generate fake log files to demo SafeStream in the live web UI and over the REST API.

    python examples/make_demo_logs.py                 # writes demo_logs/
    python examples/make_demo_logs.py --out /tmp/x --lines 200 --seed 7

Writes, for each log, the file itself (upload or drag it into the GitHub Pages
playground) and a ``<name>.request.json`` body ready for ``POST /redact`` or
``POST /scan`` (Postman: Body -> binary -> pick the file). Every value is random
and fake; nothing real is used and nothing touches the network. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import string
from pathlib import Path

# Prefixes are split so this source file is not itself flagged by secret scanners.
GH, STRIPE, SLACK, AWS = "gh" + "p_", "sk_" + "live_", "xo" + "xb-", "AK" + "IA"
CARDS = ["4111 1111 1111 1111", "5555555555554444", "3782 822463 10005", "6011111111111117"]
FIRST = ["maria", "james", "priya", "chen", "olivia", "ahmed", "sofia", "lucas", "aarav", "emma"]
LAST = ["garcia", "smith", "sharma", "wang", "brown", "khan", "rossi", "silva", "patel", "jones"]
DOMAINS = ["corpmail.com", "acme-retail.io", "northwind.net", "contoso.org"]
PATHS = ["/api/login", "/api/orders", "/api/cart", "/checkout", "/health", "/static/app.js"]
# Look-alikes that must NOT be redacted: they show precision, not just recall.
DECOYS = [
    "build sha=3f2a9c1e7b4d5a6f8e9d0c1b2a3f4e5d6c7b8a9f version=2.14.3",
    "request_id=550e8400-e29b-41d4-a716-446655440000 took 42ms",
    "cache hit ratio=0.973 entries=10240 evictions=12",
    "see docs example: user@example.com and 123-45-6789 are placeholder values",
]


def rand(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Fake:
    def __init__(self, rng: random.Random) -> None:
        self.r = rng

    def person(self) -> tuple[str, str]:
        f, last = self.r.choice(FIRST), self.r.choice(LAST)
        return f"{f.title()} {last.title()}", f"{f}.{last}@{self.r.choice(DOMAINS)}"

    def ip(self) -> str:
        a, b, c = self.r.choice([10, 172, 192, 203]), self.r.randint(0, 255), self.r.randint(0, 255)
        return f"{a}.{b}.{c}.{self.r.randint(1, 254)}"

    def ssn(self) -> str:
        return f"{self.r.randint(100, 665)}-{self.r.randint(10, 99)}-{self.r.randint(1000, 9999)}"

    def phone(self) -> str:
        return f"+1 {self.r.randint(201, 989)} 555 {self.r.randint(1000, 9999)}"

    def aws(self) -> str:
        return AWS + rand(self.r, string.ascii_uppercase + "234567", 16)

    def github(self) -> str:
        return GH + rand(self.r, string.ascii_letters + string.digits, 36)

    def stripe(self) -> str:
        return STRIPE + rand(self.r, string.ascii_letters + string.digits, 24)

    def slack(self) -> str:
        tail = rand(self.r, string.ascii_letters + string.digits, 24)
        return f"{SLACK}{self.r.randint(10**9, 10**10)}-{tail}"

    def jwt(self) -> str:
        head = b64(b'{"alg":"HS256","typ":"JWT"}')
        body = b64(json.dumps({"sub": str(self.r.randint(10**5, 10**6)), "role": "admin"}).encode())
        return f"{head}.{body}.{b64(self.r.randbytes(32))}"

    def entropy_secret(self) -> str:
        return rand(self.r, string.ascii_letters + string.digits + "+/", 40)


def app_log(f: Fake, n: int) -> str:
    out = []
    for i in range(n):
        ts = f"2026-11-19T10:{i // 60 % 60:02d}:{i % 60:02d}Z"
        name, email = f.person()
        line = f.r.choice(
            [
                f"{ts} INFO  login ok user={email} ip={f.ip()}",
                f"{ts} INFO  payment card={f.r.choice(CARDS)} ssn={f.ssn()} amount=49.99",
                f"{ts} WARN  support call from {name} <{email}> phone {f.phone()}",
                f"{ts} DEBUG deploy aws_key={f.aws()} token={f.github()}",
                f"{ts} DEBUG billing stripe_key={f.stripe()} slack={f.slack()}",
                f"{ts} INFO  session Authorization: Bearer {f.jwt()}",
                f"{ts} ERROR db connect failed postgres://app:{f.entropy_secret()[:16]}@{f.ip()}:5432/prod",
                f"{ts} INFO  {f.r.choice(DECOYS)}",
            ]
        )
        out.append(line)
    return "\n".join(out) + "\n"


def nginx_log(f: Fake, n: int) -> str:
    out = []
    for i in range(n):
        _, email = f.person()
        q = f.r.choice(["", f"?email={email}", f"?token={f.github()}", f"?ref=home&page={i}"])
        out.append(
            f"{f.ip()} - - [19/Nov/2026:10:{i // 60 % 60:02d}:{i % 60:02d} +0000] "
            f'"GET {f.r.choice(PATHS)}{q} HTTP/1.1" {f.r.choice([200, 200, 302, 404, 500])} '
            f'{f.r.randint(200, 9000)} "-" "Mozilla/5.0"'
        )
    return "\n".join(out) + "\n"


def json_log(f: Fake, n: int) -> str:
    out = []
    for i in range(n):
        name, email = f.person()
        rec = {
            "ts": f"2026-11-19T11:{i // 60 % 60:02d}:{i % 60:02d}Z",
            "level": f.r.choice(["info", "warn", "error"]),
            "event": f.r.choice(["signup", "checkout", "password_reset"]),
            "user": {"name": name, "email": email, "phone": f.phone()},
            "client_ip": f.ip(),
            "card": f.r.choice(CARDS),
            "api_key": f.stripe(),
        }
        out.append(json.dumps(rec))
    return "\n".join(out) + "\n"


def env_file(f: Fake) -> str:
    return (
        f"AWS_ACCESS_KEY_ID={f.aws()}\n"
        f"AWS_SECRET_ACCESS_KEY={f.entropy_secret()}\n"
        f"GITHUB_TOKEN={f.github()}\n"
        f"STRIPE_SECRET_KEY={f.stripe()}\n"
        f"SLACK_BOT_TOKEN={f.slack()}\n"
        f"DATABASE_URL=postgres://admin:{f.entropy_secret()[:20]}@{f.ip()}:5432/app\n"
        f"JWT_SIGNING_SECRET={f.entropy_secret()}\n"
        "LOG_LEVEL=info\nPORT=8080\n"
    )


def clean_log(f: Fake, n: int) -> str:
    """No PII at all: the UI and API should report zero findings."""
    return (
        "\n".join(f"2026-11-19T12:00:{i % 60:02d}Z INFO {f.r.choice(DECOYS[:3])}" for i in range(n))
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", default="demo_logs", help="output directory (default: demo_logs)")
    ap.add_argument("--lines", type=int, default=60, help="lines per small log (default: 60)")
    ap.add_argument("--seed", type=int, default=42, help="random seed; same seed, same files")
    args = ap.parse_args(argv)

    f = Fake(random.Random(args.seed))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "app.log": app_log(f, args.lines),
        "nginx_access.log": nginx_log(f, args.lines),
        "events.jsonl": json_log(f, args.lines),
        "prod.env": env_file(f),
        "clean.log": clean_log(f, args.lines),
        # ~1 MB: just under the live demo's 1 MiB cap, for the size/throughput demo
        "big_app.log": app_log(f, 9000),
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8", newline="\n")
        (out / f"{name}.request.json").write_text(json.dumps({"text": text}), encoding="utf-8")
        print(f"{out / name}  ({len(text.encode()):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
