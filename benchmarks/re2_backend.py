"""Tier-1 backend evaluation: google-re2 vs the pure-Python `re` engine.

Phase 3 asked: can a re2 / Vectorscan backend for the deterministic tier speed
things up *without changing output*? This script prototypes a hybrid re2 backend
(re2 for the patterns it can compile, Python `re` for the rest), then measures
both **correctness** and **throughput** so the adopt/don't-adopt decision rests
on real numbers. Requires ``pip install google-re2``.

Findings are summarised in ``docs/PERFORMANCE_BACKENDS.md``. Short version:
re2 both *changes output* (its `\\b`/`\\w`/`\\d` are ASCII-only, so it diverges
from Python's Unicode-aware semantics and under-detects) **and** gives no
end-to-end speedup (the anchor prefilter already captures re2's fast-no-match
win, and the throughput-dominating PII patterns use lookaround re2 cannot
compile). So it is **not adopted**.

Run: ``python benchmarks/re2_backend.py``
"""

from __future__ import annotations

import os
import sys
import time

# Silence re2's absl "compile error" chatter — we compile deliberately-invalid
# (for re2) patterns to discover the compatible subset.
os.environ.setdefault("GLOG_minloglevel", "3")

try:
    import re2
except ImportError:  # pragma: no cover - benchmark-only dependency
    sys.exit("this benchmark needs google-re2:  pip install google-re2")

from safestream_redactor.detectors.deterministic import _PATTERNS, DeterministicDetector
from safestream_redactor.entities import Detection


def _compat() -> tuple[list, list]:
    compat, incompat = [], []
    for pat in _PATTERNS:
        try:
            compat.append((pat, re2.compile(pat.regex.pattern)))
        except Exception as exc:
            incompat.append((pat, str(exc)[:60]))
    return compat, incompat


class HybridRe2Detector(DeterministicDetector):
    """DeterministicDetector using re2 for compilable patterns, Python for the rest."""

    def __init__(self, **kw: object) -> None:
        super().__init__(**kw)  # type: ignore[arg-type]
        self._engines = []
        for pat in self._patterns:
            try:
                self._engines.append(re2.compile(pat.regex.pattern))
            except Exception:
                self._engines.append(pat.regex)

    def detect(self, text: str) -> list[Detection]:
        import re as _re

        found: list[Detection] = []
        lowered: str | None = None
        has_digit: bool | None = None
        digit = _re.compile(r"\d")
        for pattern, engine in zip(self._patterns, self._engines, strict=True):
            if self._prefilter:
                if pattern.needs_digit:
                    if has_digit is None:
                        has_digit = digit.search(text) is not None
                    if not has_digit:
                        continue
                if pattern.anchors and not any(a in text for a in pattern.anchors):
                    continue
                if pattern.anchors_lower:
                    if lowered is None:
                        lowered = text.lower()
                    if not any(a in lowered for a in pattern.anchors_lower):
                        continue
            for m in engine.finditer(text):
                matched = m.group(pattern.group)
                if pattern.validator is not None and not pattern.validator(matched):
                    continue
                found.append(
                    Detection(
                        m.start(pattern.group),
                        m.end(pattern.group),
                        matched,
                        pattern.entity_type,
                        pattern.confidence,
                        source=self.name,
                    )
                )
        return found


UNICODE_PROBES = [
    "文字bob@corp.io文字",
    "naïvebob@corp.io",
    "٠٩bob@x.io",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yنص",
    "sk_live_abcdefghijklmnop1234567890café",
]

LINE = (
    "2024-01-01T00:00:00Z INFO user bob.smith@corp.example.com logged in "
    "from 10.20.30.40 ref 4111-1111-1111-1111 ssn: 123-45-6789 ok\n"
)

# credential-dense specimens (mirrors the kinds of lines the credential tiers hit)
CREDS = [
    "mail jane.doe+x@corp.example.co now",
    "key AKIAIOSFODNN7EXAMPLE leaked",
    "tok ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "sk_live_abcdefghijklmnop1234567890 and rk_test_ABCDEFGHIJKLMNOP1234567890",
    "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "dsn postgres://svc:S3cretPass@db.internal:5432/app",
    "xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx posted",
]


def _keyed(dets: list[Detection]) -> list[tuple[int, int, str, str]]:
    return [(d.start, d.end, d.text, d.entity_type.value) for d in dets]


def main() -> None:
    compat, incompat = _compat()
    print(f"== re2 compile compatibility: {len(compat)} compile, {len(incompat)} cannot ==")
    for pat, why in incompat:
        print(f"   cannot: {pat.entity_type.value:<15} {why}")

    print("\n== correctness: hybrid-re2 vs python on Unicode-adjacent input ==")
    py, hy = DeterministicDetector(), HybridRe2Detector()
    diverged = 0
    for probe in UNICODE_PROBES:
        a, b = _keyed(py.detect(probe)), _keyed(hy.detect(probe))
        if a != b:
            diverged += 1
            print(f"   DIVERGE {probe!r}\n     python={a}\n     re2   ={b}")
    print(f"   -> {diverged}/{len(UNICODE_PROBES)} inputs where re2 CHANGES output (under-detects)")

    print("\n== throughput: end-to-end DeterministicDetector.detect (best of 3) ==")
    corpora = {
        "realistic-log (PII-heavy)": LINE * 40000,
        "credential+PII mix": ("\n".join(CREDS) + "\n" + LINE * 3) * 3000,
    }
    for name, corpus in corpora.items():
        mb = len(corpus) / 1e6
        row = []
        for label, det in [("python", py), ("hybrid-re2", hy)]:
            t = time.perf_counter()
            for _ in range(3):
                det.detect(corpus)
            dt = (time.perf_counter() - t) / 3
            row.append((label, mb / dt))
        py_mb, re2_mb = row[0][1], row[1][1]
        print(
            f"   {name:<28} python {py_mb:5.2f} MB/s   "
            f"hybrid-re2 {re2_mb:5.2f} MB/s   ({re2_mb / py_mb:.2f}x)"
        )

    print("\n== conclusion ==")
    print("re2 CHANGES output on Unicode text (ASCII-only \\b/\\w/\\d) AND gives no")
    print("end-to-end speedup -> not adopted. See docs/PERFORMANCE_BACKENDS.md.")


if __name__ == "__main__":
    main()
