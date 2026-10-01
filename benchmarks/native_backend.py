"""Native (Rust) detection core — speedup report vs the Python tier.

Measures the optional native core (`native/`, built with maturin) against the
Python ``DeterministicDetector`` on the SAME pattern set, so the comparison is
apples-to-apples. Also asserts byte-identity (spans/types) as a sanity gate — the
authoritative gate is ``tests/test_native_backend.py``.

Build + run:
    (cd native && maturin build --release --out dist) && \
        pip install --force-reinstall --no-deps native/dist/*.whl
    python benchmarks/native_backend.py

Current slice: the 12 lookaround-free credential patterns, SSN/IPv4/IPv6
(lookaround-free candidate + boundary check + validator), and credit_card and the
two phone patterns (hand-written linear scanners). The digit-gated patterns are
the real bottleneck class: no distinctive literal, so Python must run them on
every digit-bearing line.
"""

from __future__ import annotations

import random
import sys
import time

try:
    import safestream_native as sn
except ImportError:
    sys.exit(
        "native core not installed — build it: (cd native && maturin build --release --out dist)"
    )

from safestream_redactor.detectors.deterministic import DeterministicDetector
from safestream_redactor.entities import EntityType

_CREDS = [
    "mail jane.doe+x@corp.example.co now",
    "key AKIAIOSFODNN7EXAMPLE leaked",
    "tok ghp_abcdefghijklmnopqrstuvwxyz0123456789 used",
    "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "npm npm_abcdefghijklmnopqrstuvwxyz0123456789 published",
    "ssn 123-45-6789 on file",  # digit-gated PII: the real bottleneck class
    "client 10.20.30.40 connected",  # ipv4: digit-gated + validator
    "card 4111 1111 1111 1111 charged",  # credit_card: linear scanner + Luhn
    "call +1 (415) 555-0123 back",  # structured phone
]
# Distractor carries digits, so the SSN pattern (digit-gated, no literal prefilter)
# cannot be prefilter-skipped in Python and must run its regex on every line.
_DISTRACT = "2024-01-05T00:00:03Z INFO req 3bd3 latency 42ms status 200 id 96046 bytes 76323"


def _corpus(mb: int, pii_frac: float, seed: int = 3) -> str:
    rng = random.Random(seed)
    out: list[str] = []
    n = 0
    target = mb * 1024 * 1024
    while n < target:
        line = (rng.choice(_CREDS) if rng.random() < pii_frac else _DISTRACT) + "\n"
        out.append(line)
        n += len(line)
    return "".join(out)


def _best(fn, text: str, repeat: int = 3) -> float:
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn(text)
        best = min(best, time.perf_counter() - t0)
    return best


def main() -> None:
    covered = {p[0] for p in sn.patterns()}
    types = [EntityType.from_name(n) for n in covered]
    pydet = DeterministicDetector(types=types, prefilter=True)

    print(
        f"native slice: {len(sn.patterns())} patterns "
        "(17 credential + ssn/ipv4/ipv6 + credit_card + 2 phone)"
    )
    print(f"{'corpus':<22} {'matches':>9} {'python':>12} {'native':>12} {'speedup':>8}")
    print("-" * 66)
    for label, frac in [("none (0% PII)", 0.0), ("sparse (1%)", 0.01), ("dense (50%)", 0.5)]:
        text = _corpus(5, frac)
        mb = len(text) / 1e6
        py = sorted((d.start, d.end, d.entity_type.value) for d in pydet.detect(text))
        nat = sorted((s, e, ty) for s, e, ty, _ in sn.scan_text(text))
        assert py == nat, f"native diverged from python on {label} ({len(py)} vs {len(nat)})"
        tp = _best(pydet.detect, text)
        tn = _best(sn.scan_text, text)
        print(f"{label:<22} {len(py):>9} {mb / tp:>9.1f}MB/s {mb / tn:>9.1f}MB/s {tp / tn:>7.1f}x")

    # Unicode byte-identity sanity (offsets must be character indices)
    u = "文字 a@b.io 文 key AKIAIOSFODNN7EXAMPLE"
    assert sorted((s, e, ty) for s, e, ty, _ in sn.scan_text(u)) == sorted(
        (d.start, d.end, d.entity_type.value) for d in pydet.detect(u)
    ), "native diverged on Unicode"
    print("\nbyte-identical to Python (incl. Unicode char offsets): OK")


if __name__ == "__main__":
    main()
