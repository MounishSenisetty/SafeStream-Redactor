"""What each redaction mode costs, whether encryption round-trips, and SARIF validity.

* **Overhead** per mode (replace, mask, hash, pseudonymize, encrypt, fictionalize) on
  ``--mb`` MiB of AgentTrace text: end-to-end MB/s of ``Redactor.redact`` (detection
  included), rendering cost in microseconds per detection (``policy.apply`` over
  precomputed detections), and output inflation (bytes out / bytes in).
* **Round-trip**: encrypt then ``Deanonymizer.restore`` must give back the input
  exactly.
* **Tamper**: ``--tamper`` encrypted tokens, each with one random bit flipped in its
  payload, must all fail to restore (fail closed).
* **SARIF** (``--sarif``): the report built from AgentTrace detections is validated
  against the official SARIF 2.1.0 JSON schema, and its cost per 1,000 findings is
  measured.

    python -m benchmarks.policy_overhead --mb 16 --tamper 10000 --sarif --json out.json
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import time
import urllib.request
from pathlib import Path
from typing import Any

from benchmarks import corpora

MODES = ["replace", "mask", "hash", "pseudonymize", "encrypt", "fictionalize"]
KEY = b"conference-study-key-0123456789ab"  # benchmark key, never a secret
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/"
    "sarif-schema-2.1.0.json"
)


def corpus_text(mb: float) -> str:
    base = "\n".join(d.text for d in corpora.load("agent_traces").docs)
    text = base
    while len(text) < mb * (1 << 20):
        text += "\n" + base
    return text[: int(mb * (1 << 20))]


def policy(mode: str) -> Any:
    from safestream_redactor import RedactionPolicy

    keys: dict[str, Any] = {}
    if mode in ("pseudonymize", "fictionalize"):
        keys["hmac_key"] = KEY
    if mode == "hash":
        keys["hash_salt"] = KEY
    if mode == "encrypt":
        keys["encrypt_key"] = KEY
    return RedactionPolicy(mode=mode, **keys)


def overhead(text: str) -> dict[str, Any]:
    from safestream_redactor import Redactor

    detections = Redactor(load_plugins=False, backend="native").detect(text)
    out: dict[str, Any] = {"input_bytes": len(text.encode()), "detections": len(detections)}
    for mode in MODES:
        r = Redactor(load_plugins=False, backend="native", policy=policy(mode))
        t = time.perf_counter()
        redacted = r.redact(text)
        e2e = time.perf_counter() - t
        t = time.perf_counter()
        r.policy.apply(text, detections)
        render = time.perf_counter() - t
        out[mode] = {
            "e2e_mb_s": len(text.encode()) / 1e6 / e2e,
            "render_us_per_detection": 1e6 * render / max(1, len(detections)),
            "inflation": len(redacted.encode()) / len(text.encode()),
        }
        print(
            f"{mode:13} {out[mode]['e2e_mb_s']:.2f} MB/s  "
            f"{out[mode]['render_us_per_detection']:.2f} us/det",
            flush=True,
        )
    return out


def roundtrip(text: str, tamper: int, seed: int = 0) -> dict[str, Any]:
    from safestream_redactor import Redactor
    from safestream_redactor.operators import _TOKEN, Deanonymizer

    r = Redactor(load_plugins=False, backend="native", policy=policy("encrypt"))
    redacted = r.redact(text)
    d = Deanonymizer(KEY)
    exact = d.restore(redacted) == text
    tokens = [m.group(0) for m in _TOKEN.finditer(redacted)]
    rng = random.Random(seed)
    restored = 0
    for i in range(tamper):
        # flip one random bit of the decoded nonce+ciphertext+tag, then re-encode
        # with the same grouping (a flip in base64 padding bits would change nothing)
        head, payload = tokens[i % len(tokens)][:-1].split(":E:", 1)
        raw = bytearray(base64.urlsafe_b64decode(payload.replace(".", "") + "=="))
        raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        enc = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        grouped = ".".join(enc[j : j + 16] for j in range(0, len(enc), 16))
        dd = Deanonymizer(KEY)
        dd.restore(f"{head}:E:{grouped}>")
        restored += dd.restored
    return {
        "tokens": len(tokens),
        "roundtrip_exact": exact,
        "restored_tokens": d.restored,
        "tampered": tamper,
        "tampered_restored": restored,
    }


def sarif(text_docs: list[str]) -> dict[str, Any]:
    import jsonschema

    from safestream_redactor import Redactor, __version__
    from safestream_redactor.sarif import Finding, build_sarif

    r = Redactor(load_plugins=False, backend="native")
    findings = [
        Finding(d.entity_type, d.start, d.end, d.confidence, d.source, uri=f"doc{i}.txt")
        for i, text in enumerate(text_docs)
        for d in r.detect(text)
    ]
    t = time.perf_counter()
    report = json.dumps(build_sarif(findings, version=__version__))
    cost = time.perf_counter() - t
    with urllib.request.urlopen(SARIF_SCHEMA, timeout=60) as resp:
        schema = json.loads(resp.read())
    errors = list(jsonschema.Draft7Validator(schema).iter_errors(json.loads(report)))
    return {
        "findings": len(findings),
        "valid": not errors,
        "schema_errors": [e.message[:200] for e in errors[:5]],
        "ms_per_1000_findings": 1000 * cost / max(1, len(findings)) * 1000,
        "bytes_per_finding": len(report) / max(1, len(findings)),
        "schema": SARIF_SCHEMA,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mb", type=float, default=16)
    ap.add_argument("--tamper", type=int, default=10000)
    ap.add_argument("--sarif", action="store_true")
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    from benchmarks.harness import environment
    from benchmarks.mcp_egress_audit import _code_commit

    text = corpus_text(args.mb)
    report: dict[str, Any] = {"environment": environment(), "code": _code_commit(), "mb": args.mb}
    report["overhead"] = overhead(text)
    report["roundtrip"] = roundtrip(corpus_text(1), args.tamper)
    print(report["roundtrip"], flush=True)
    if args.sarif:
        report["sarif"] = sarif([d.text for d in corpora.load("agent_traces").docs])
        print({k: v for k, v in report["sarif"].items() if k != "schema"}, flush=True)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
