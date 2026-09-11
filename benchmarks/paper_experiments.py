"""Reproducible experiments for the SafeStream-Redactor research paper.

Every number in the paper's evaluation is produced here (except the synthetic
precision/recall, which comes from ``run_benchmark.py``, and the 1 GB memory
proof, which is ``tests/test_memory.py -m memory``). Run:

    python benchmarks/paper_experiments.py

The output is deterministic (fixed seeds); absolute throughput is
environment-dependent, so the paper reports the machine it was measured on.
No real secrets are used — all specimens are synthetic.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import tracemalloc

from safestream_redactor import Redactor
from safestream_redactor.parallel import redact_file_parallel

# Synthetic specimens (never real secrets).
_SPECIMENS = {
    "email": "alice.roberts@example.com",
    "ssn": "123-45-6789",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "private_key": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"
    ),
}
_CREDENTIAL_SPECIMENS = {
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "slack_token": "xoxb-2345678901-2345678901-AbCdEfGhIjKlMnOpQrStUvWx",
    "stripe_key": "sk_live_abcdefghijklmnop1234567890",
    "google_api_key": "AIzaSy0123456789abcdefghijklmnopqrstuvw",
    "sendgrid_key": "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEXY",
    "npm_token": "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
    "private_key": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"
    ),
}


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _redact_file(redactor: Redactor, text: str) -> str:
    d = tempfile.mkdtemp()
    inp, out = os.path.join(d, "in"), os.path.join(d, "out")
    with open(inp, "w", encoding="utf-8") as f:
        f.write(text)
    redactor.redact_file(inp, out)
    with open(out, encoding="utf-8") as f:
        result = f.read()
    for p in (inp, out):
        os.remove(p)
    os.rmdir(d)
    return result


_FILLER = "the quick brown fox jumps over the lazy dog. "  # word chars + spaces


def exp_boundary_correctness() -> None:
    """E2 (flagship): overlap-off vs overlap-on across every interior split.

    For each specimen and every offset ``off`` (0<off<len), build a document in
    which a fixed-size chunk boundary falls exactly at ``secret[off]`` -- i.e. the
    secret straddles a chunk seam. The secret is separated from surrounding text
    by spaces, so it is a valid detection in the whole-document reference. We then
    redact with naive chunking (overlap=0, each chunk processed independently) and
    with overlap-aware streaming (overlap>=L_max) and check whether the secret
    survives verbatim in the output (a *leak*). Both configurations stream over
    many 64-byte chunks; only the overlap differs.
    """
    print("\n== E2. Boundary correctness (overlap ablation) ==")
    chunk = 64
    overlap = 256  # >= every specimen length here; the set's L_max
    naive_r = Redactor(chunk_size=chunk, overlap=0, load_plugins=False)
    safe_r = Redactor(chunk_size=chunk, overlap=overlap, load_plugins=False)
    ref_r = Redactor(chunk_size=1 << 30, overlap=overlap, load_plugins=False)  # whole-document
    hdr = f"{'entity':<14}{'splits':>7}{'leak@0':>8}{'leak@256':>10}{'mism@0':>8}{'mism@256':>10}"
    print(hdr)
    tot = {"split": 0, "leak0": 0, "leakO": 0, "mis0": 0, "misO": 0}
    for name, secret in _SPECIMENS.items():
        row = {"split": 0, "leak0": 0, "leakO": 0, "mis0": 0, "misO": 0}
        for off in range(1, len(secret)):
            # start the secret so that a boundary k*chunk lands at start+off,
            # with >= `overlap` chars of filler before it and a space just before
            start = chunk * 8 + ((chunk - (off % chunk)) % chunk)
            pre = (_FILLER * (start // len(_FILLER) + 1))[: start - 1] + " "
            assert len(pre) == start and pre[-1] == " "
            doc = pre + secret + " tail. " + _FILLER * 4 + "\n"
            assert (start + off) % chunk == 0 and 0 < off < len(secret)  # boundary is interior
            ref = _redact_file(ref_r, doc)
            naive = _redact_file(naive_r, doc)
            safe = _redact_file(safe_r, doc)
            row["split"] += 1
            row["leak0"] += secret in naive  # full secret survives verbatim
            row["leakO"] += secret in safe
            row["mis0"] += naive != ref  # any deviation from whole-document reference
            row["misO"] += safe != ref
        print(
            f"{name:<14}{row['split']:>7}{row['leak0']:>8}{row['leakO']:>10}"
            f"{row['mis0']:>8}{row['misO']:>10}"
        )
        for k in tot:
            tot[k] += row[k]
    print(
        f"{'TOTAL':<14}{tot['split']:>7}{tot['leak0']:>8}{tot['leakO']:>10}"
        f"{tot['mis0']:>8}{tot['misO']:>10}"
    )
    s = tot["split"]
    print(
        f"naive: verbatim-leak {tot['leak0']}/{s} = {tot['leak0'] / s:.1%}, "
        f"incorrect-vs-reference {tot['mis0']}/{s} = {tot['mis0'] / s:.1%}"
    )
    print(
        f"overlap-safe: verbatim-leak {tot['leakO']}/{s}, "
        f"incorrect-vs-reference {tot['misO']}/{s} "
        f"(0 == byte-identical to whole-document; Theorem 1)"
    )


def exp_tier_ablation() -> None:
    """E3: what each tier adds, on inputs designed to exercise it."""
    print("\n== E3. Tier ablation (illustrative) ==")
    # (a) entropy tier: an unlabeled high-entropy secret with no published format
    unlabeled = "session = Xr7bQp2Lm9Zk4Tn8Wv3Yd6Fs1Hg0Jc9Ab in the log"
    det_only = Redactor(use_entropy=False).redact(unlabeled)
    with_ent = Redactor(use_entropy=True).redact(unlabeled)
    print("unlabeled high-entropy secret:")
    print(f"  deterministic-only : {det_only!r}")
    print(f"  +entropy           : {with_ent!r}")
    # (b) contextual tier: a bare SSN below threshold is promoted by a nearby cue
    bare = "the customer ssn: 123-45-6789 is on file"
    # contextual scorer is part of the default cascade; compare against a config
    # that runs only the deterministic tier (no contextual promotion/suppression)
    from safestream_redactor.detectors.deterministic import DeterministicDetector
    from safestream_redactor.entities import EntityType

    det = DeterministicDetector()
    raw = [d for d in det.detect(bare) if d.entity_type == EntityType.SSN]
    full = Redactor(min_confidence=0.5).detect(bare)
    print("bare SSN next to an 'ssn:' cue (threshold 0.5):")
    print(f"  deterministic raw conf : {raw[0].confidence if raw else None}")
    print(f"  full cascade detects   : {[d.entity_type.value for d in full]}")
    # (c) contextual suppression of a placeholder-looking value
    placeholder = "example ssn 000-00-0000 (not real)"
    supp = Redactor(min_confidence=0.5).detect(placeholder)
    print(f"placeholder-looking SSN suppressed by cascade: detected={len(supp)}")


def exp_credential_coverage() -> None:
    """E4: unified PII+credential coverage — classes detected out of the box."""
    print("\n== E4. Credential/secret coverage ==")
    r = Redactor(min_confidence=0.0)
    hits = 0
    for name, secret in _CREDENTIAL_SPECIMENS.items():
        got = {d.entity_type.value for d in r.detect(f"token {secret} end")}
        ok = bool(got)
        hits += ok
        print(f"  {name:<14} {'DETECTED' if ok else 'MISSED':<9} -> {sorted(got)}")
    print(f"credential/secret classes detected: {hits}/{len(_CREDENTIAL_SPECIMENS)}")
    print(
        "(PII-only pattern systems — e.g. Presidio's predefined recognizers — "
        "cover none of these credential classes by design)"
    )


def _corpus(mb: float, seed: int = 7) -> str:
    import random

    rng = random.Random(seed)
    pii = [
        "user alice.roberts@example.com logged in",
        "client ip 10.20.30.40 connected",
        "card 4111 1111 1111 1111 charged",
        "ssn 123-45-6789 on file",
        "key AKIAIOSFODNN7EXAMPLE rotated",
        "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 used",
    ]
    distract = "2024-01-05T00:00:03Z INFO req 3bd3 latency 42ms status 200 id 96046 bytes 76323"
    out, n, target = [], 0, int(mb * 1024 * 1024)
    while n < target:
        line = (rng.choice(pii) if rng.random() < 0.1 else distract) + "\n"
        out.append(line)
        n += len(line)
    return "".join(out)


def exp_parallel() -> None:
    """E5: parallel speedup and byte-identity vs sequential."""
    print("\n== E5. Parallel speedup + byte-identity ==")
    text = _corpus(40)
    d = tempfile.mkdtemp()
    inp = os.path.join(d, "in.txt")
    with open(inp, "w", encoding="utf-8") as f:
        f.write(text)
    mb = os.path.getsize(inp) / 1e6
    r = Redactor(load_plugins=False)

    def timed(fn) -> float:
        best = float("inf")
        for _ in range(3):
            t0 = time.perf_counter()
            fn()
            best = min(best, time.perf_counter() - t0)
        return best

    seq_out = os.path.join(d, "seq")
    t_seq = timed(lambda: r.redact_file(inp, seq_out))
    seq_hash = _sha256(seq_out)
    print(f"{'workers':>8}{'MB/s':>10}{'speedup':>9}{'byte-identical':>16}")
    print(f"{1:>8}{mb / t_seq:>10.2f}{1.0:>9.2f}{'(reference)':>16}")
    for k in (2, 4):
        out = os.path.join(d, f"par{k}")
        t = timed(lambda out=out, k=k: redact_file_parallel(r, inp, out, workers=k))
        identical = "yes" if _sha256(out) == seq_hash else "NO"
        print(f"{k:>8}{mb / t:>10.2f}{t_seq / t:>9.2f}{identical:>16}")
        os.remove(out)
    os.remove(inp)
    os.remove(seq_out)
    os.rmdir(d)


def exp_memory() -> None:
    """E6: peak Python heap is flat across input sizes (constant memory)."""
    print("\n== E6. Constant memory (peak Python heap vs input size) ==")
    r = Redactor(chunk_size=64 * 1024, overlap=8 * 1024, load_plugins=False)
    print(f"{'input MB':>10}{'peak heap MB':>14}")
    for mb in (16, 32, 64):
        text = _corpus(mb)
        d = tempfile.mkdtemp()
        inp, out = os.path.join(d, "in"), os.path.join(d, "out")
        with open(inp, "w", encoding="utf-8") as f:
            f.write(text)
        tracemalloc.start()
        r.redact_file(inp, out)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"{mb:>10}{peak / 1e6:>14.2f}")
        os.remove(inp)
        os.remove(out)
        os.rmdir(d)


_EXPERIMENTS = {
    "boundary": exp_boundary_correctness,
    "tiers": exp_tier_ablation,
    "coverage": exp_credential_coverage,
    "parallel": exp_parallel,
    "memory": exp_memory,
}

if __name__ == "__main__":
    import sys

    chosen = sys.argv[1:] or list(_EXPERIMENTS)
    for name in chosen:
        _EXPERIMENTS[name]()
