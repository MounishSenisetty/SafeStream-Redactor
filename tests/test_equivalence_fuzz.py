# ruff: noqa: RUF001  (adversarial Unicode is the point of this file)
"""Differential equivalence fuzzer: whole == streaming == parallel.

Mechanically exercises the core theorem (``docs/FORMAL_MODEL.md``, Theorems 1-2)::

    Redact_whole(Doc) == Redact_streaming(Doc) == Redact_parallel(Doc)

Three executions of the same redactor are compared byte-for-byte against the
whole-document reference ``Redactor.redact`` on every generated document:

* **streaming** -- ``redact_stream`` over a random chunking (1 char .. multi-KB),
  and the real file path ``redact_file`` with a random ``chunk_size``;
* **parallel**  -- ``redact_file_parallel`` with a random worker count.

Inputs are adversarial in the ways the theorem's proof is sensitive to:

* arbitrary Unicode noise (astral code points, combining marks, NUL, CR/LF/LS/PS,
  multi-byte UTF-8) and raw undecodable bytes (U+FFFD paths);
* structured PII (emails, Luhn-valid cards, IPv4, SSNs, AWS keys, custom words)
  placed *on purpose* straddling a chunk boundary, the engine's emit boundary
  (``len(buffer) - overlap``), the rescan-prefix edge, and every parallel seam
  (seams are read from ``plan_ranges`` itself, then entities are written across
  them with size-preserving overwrites so the seams do not move).

Soundness of the oracle: the theorem's premise is ``overlap >= L_max`` (longest
span emitted). Each example is therefore guarded with ``assume`` on the
whole-document detections, so a counterexample is a real violation of the theorem
rather than an out-of-contract input. On failure the assertion reports the
execution mode, parameters, first differing offset with surrounding context, and
Hypothesis shrinks the document to a minimal counterexample.

Profiles: ``HYPOTHESIS_PROFILE=ci`` (default; derandomized, fast) or ``deep``
(``SAFESTREAM_FUZZ_EXAMPLES`` examples, randomized -- run before a release or
overnight). Rust: ``native/tests/properties.rs`` already holds the ``proptest``
parity gate; this file additionally runs every property against
``backend="native"`` whenever the extension is installed.
"""

from __future__ import annotations

import importlib.util
import os
import string
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, event, given, note, settings
from hypothesis import strategies as st

import safestream_redactor.parallel as par
from safestream_redactor import Redactor
from safestream_redactor.parallel import redact_file_parallel

BACKENDS = ["python"] + (["native"] if importlib.util.find_spec("safestream_native") else [])

settings.register_profile(
    "ci",
    max_examples=60,
    derandomize=True,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile(
    "deep",
    max_examples=int(os.environ.get("SAFESTREAM_FUZZ_EXAMPLES", "2000")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
PROFILE = settings.get_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

CUSTOM_WORD = "ProjectX"
# the contextual scorer reads a 48-char left window; every overlap below clears it
OVERLAPS = [128, 256, 512, 1024]


# --------------------------------------------------------------------------
# oracle + the three executions
# --------------------------------------------------------------------------


def make_redactor(overlap: int, chunk_size: int, backend: str) -> Redactor:
    # allow_unsafe_overlap only silences the *static* 8 KiB default of the built-in
    # tiers; the actual premise (every emitted span <= overlap) is enforced per
    # example by ``assume`` below, which is the exact condition of Theorem 1.
    return Redactor(
        custom_words=[CUSTOM_WORD],
        overlap=overlap,
        chunk_size=chunk_size,
        backend=backend,
        load_plugins=False,
        allow_unsafe_overlap=True,
    )


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def whole(r: Redactor, data: bytes) -> bytes:
    return r.redact(decode(data)).encode("utf-8")


def in_contract(r: Redactor, data: bytes) -> None:
    """Discard inputs outside Theorem 1's premise (a span longer than the window)."""
    spans = [d.end - d.start for d in r.detect(decode(data))]
    assume(max(spans, default=0) <= r.overlap)


def chunks_of(text: str, sizes: list[int]):
    """Cut ``text`` into chunks cycling through ``sizes`` (each >= 1)."""
    i = k = 0
    while i < len(text):
        n = sizes[k % len(sizes)]
        yield text[i : i + n]
        i += n
        k += 1


def streaming(r: Redactor, data: bytes, sizes: list[int]) -> bytes:
    return "".join(r.redact_stream(chunks_of(decode(data), sizes))).encode("utf-8")


def sequential_file(r: Redactor, data: bytes, tmp: Path) -> bytes:
    src, out = tmp / "seq_in.bin", tmp / "seq_out.bin"
    src.write_bytes(data)
    r.redact_file(src, out)
    return out.read_bytes()


def parallel(r: Redactor, data: bytes, workers: int, tmp: Path):
    src, out = tmp / "par_in.bin", tmp / "par_out.bin"
    src.write_bytes(data)
    outcome = redact_file_parallel(r, str(src), str(out), workers=workers)
    return out.read_bytes(), outcome


def assert_identical(mode: str, got: bytes, want: bytes, **params) -> None:
    """Byte-equality with a self-contained counterexample report."""
    if got == want:
        return
    i = next(
        (k for k, (a, b) in enumerate(zip(got, want, strict=False)) if a != b),
        min(len(got), len(want)),
    )
    lo, hi = max(0, i - 40), i + 40
    raise AssertionError(
        f"\nEQUIVALENCE VIOLATED in mode={mode} params={params}\n"
        f"  whole    len={len(want)}  ...{want[lo:hi]!r}...\n"
        f"  {mode:<8} len={len(got)}  ...{got[lo:hi]!r}...\n"
        f"  first difference at byte {i}"
    )


# --------------------------------------------------------------------------
# generators
# --------------------------------------------------------------------------


def word(alphabet: str, lo: int, hi: int):
    """A string over ``alphabet`` built from integer-indexed draws.

    Deliberately not ``st.text(alphabet=...)``: with several differently-alphabeted
    ``st.text`` nodes in one ``one_of`` Hypothesis 6.168 can crash while shrinking
    (``IntervalSet.index``), which would hide the minimal counterexample.
    """
    return st.lists(st.sampled_from(alphabet), min_size=lo, max_size=hi).map("".join)


_digits = word(string.digits, 15, 15)


def _luhn_card(body: str) -> str:
    return _finish_luhn("4" + body[:14])


def _finish_luhn(prefix: str) -> str:
    """Append the check digit that makes ``prefix + digit`` pass Luhn."""
    for check in "0123456789":
        s = prefix + check
        total = 0
        for i, ch in enumerate(reversed(s)):
            d = int(ch)
            if i % 2 == 1:
                d *= 2
                d -= 9 if d > 9 else 0
            total += d
        if total % 10 == 0:
            return s
    raise AssertionError("unreachable")


_user = st.builds(
    lambda h, t: h + t,
    st.sampled_from(string.ascii_lowercase),
    word(string.ascii_lowercase + string.digits + "._+-", 0, 10),
)
_label = word(string.ascii_lowercase, 2, 8)
_octet = st.integers(0, 255)

entities = st.one_of(
    st.builds(lambda u, a, b: f"{u}@{a}.{b}.example.com", _user, _label, _label),
    _digits.map(_luhn_card),
    st.builds(lambda *o: ".".join(map(str, o)), _octet, _octet, _octet, _octet),
    st.builds(
        lambda a, b, c: f"{a:03d}-{b:02d}-{c:04d}",
        st.integers(100, 665),
        st.integers(1, 99),
        st.integers(1, 9999),
    ),
    word(string.digits + string.ascii_uppercase, 16, 16).map("AKIA".__add__),
    st.just(CUSTOM_WORD),
    st.just("password: hunter2hunter2hunter2"),
)

# adversarial characters: astral, combining, control, every line terminator,
# multi-byte BMP, a literal replacement char, and plain letters
_specials = st.sampled_from(
    ["\r\n", "\r", "\n", "\x00", "\x0b", " ", " ", "﻿", "�", "é", "ß", "文", "𝕏", "🔐", "é"]
)
noise = st.one_of(
    _specials,
    st.text(
        alphabet=st.characters(),
        max_size=24,
    ),
)
# separators contain no alphanumerics, so neighbouring tokens never fuse into an
# unbounded entity
separators = st.sampled_from([" ", "\n", "\r\n", " | ", ", ", "\t", " ", " 　 "])

pieces = st.one_of(entities, entities, noise)
documents = st.lists(st.tuples(pieces, separators), max_size=30).map(
    lambda ps: "".join(a + s for a, s in ps)
)

# chunk sizes: 1 char up to multi-KB, plus pathological 1,2,3 cycles
chunk_sizes = st.lists(
    st.sampled_from([1, 2, 3, 7, 16, 31, 64, 255, 1024, 4096, 9000]), min_size=1, max_size=4
)

_FILLER = "lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"


def _filler(n: int) -> str:
    return (_FILLER * (n // len(_FILLER) + 1))[:n]


@st.composite
def boundary_documents(draw):
    """A filler document with entities written across engine boundaries.

    Anchors cover the chunk boundary ``m*chunk``, the emit boundary
    ``m*chunk - overlap`` (the engine emits ``len(buffer) - overlap`` of each
    pass) and the rescan-prefix edge ``m*chunk + overlap``; the entity's start is
    jittered so the boundary lands strictly *inside* it. Returns
    ``(text, chunk_size, overlap, anchor_kind)``.
    """
    overlap = draw(st.sampled_from(OVERLAPS))
    chunk = draw(st.sampled_from([1, 5, 33, 128, 500, 1024, 3000]))
    n_entities = draw(st.integers(1, 5))
    length = draw(st.integers(overlap * 3, overlap * 3 + 6000))
    text = list(_filler(length))
    for _ in range(n_entities):
        e = draw(entities)
        kind = draw(st.sampled_from(["chunk", "emit", "prefix"]))
        m = draw(st.integers(1, max(1, (length // max(chunk, 1)) - 1)))
        anchor = {"chunk": m * chunk, "emit": m * chunk - overlap, "prefix": m * chunk + overlap}[
            kind
        ]
        pos = anchor - draw(st.integers(1, max(1, len(e) - 1)))
        pos = max(0, min(pos, length - len(e) - 1))
        text[pos : pos + len(e)] = list(e)  # size-preserving overwrite
    return "".join(text)[:length], chunk, overlap


@st.composite
def seam_layouts(draw):
    """``(filler bytes, workers, overlap)`` for the parallel property.

    The file size is fixed here, before any entity is written, because
    ``plan_ranges`` -- the code under test -- chooses its seams from the size
    alone. The property then writes entities over the filler *in place* (size
    preserved), so the seams it asked for do not move.
    """
    overlap = draw(st.sampled_from([128, 256]))
    workers = draw(st.integers(2, 5))
    size = draw(st.integers(8200, 26000))
    return bytearray(_filler(size).encode()), workers, overlap


# --------------------------------------------------------------------------
# properties
# --------------------------------------------------------------------------


@pytest.mark.parametrize("backend", BACKENDS)
@settings(PROFILE)
@given(
    doc=documents,
    sizes=chunk_sizes,
    overlap=st.sampled_from(OVERLAPS),
    chunk_size=st.sampled_from([1, 64, 4096]),
)
def test_streaming_equals_whole_on_arbitrary_documents(
    backend, doc, sizes, overlap, chunk_size, tmp_path_factory
):
    """Whole == streaming (random chunking) == sequential file path, any Unicode."""
    data = doc.encode("utf-8")
    r = make_redactor(overlap, chunk_size, backend)
    in_contract(r, data)
    want = whole(r, data)
    assert_identical(
        "stream", streaming(r, data, sizes), want, sizes=sizes, overlap=overlap, backend=backend
    )
    tmp = tmp_path_factory.mktemp("fz")
    assert_identical(
        "file", sequential_file(r, data, tmp), want, chunk_size=chunk_size, overlap=overlap
    )


@pytest.mark.parametrize("backend", BACKENDS)
@settings(PROFILE)
@given(
    case=boundary_documents(),
    sizes=st.lists(st.sampled_from([1, 3, 64, 1000]), min_size=1, max_size=3),
)
def test_entities_straddling_window_and_chunk_boundaries(backend, case, sizes):
    """No detection is truncated, missed or duplicated at a chunk/emit/prefix edge."""
    text, chunk, overlap = case
    data = text.encode("utf-8")
    r = make_redactor(overlap, chunk, backend)
    in_contract(r, data)
    want = whole(r, data)
    # input chunks aligned to the engine's own chunk size AND a random cut cycle
    assert_identical(
        "stream/aligned", streaming(r, data, [chunk]), want, chunk=chunk, overlap=overlap
    )
    assert_identical("stream/random", streaming(r, data, sizes), want, sizes=sizes, overlap=overlap)
    note(f"redactions={want.count(b'[REDACTED]')}")
    event(f"redactions={min(want.count(b'[REDACTED]'), 5)}")


@pytest.mark.parametrize("backend", BACKENDS)
@settings(PROFILE, max_examples=max(10, PROFILE.max_examples // 3))
@given(data=st.data())
def test_parallel_equals_whole_with_entities_on_every_seam(backend, data, tmp_path_factory):
    """Whole == parallel, with an entity or invalid bytes written across each seam."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(par, "MIN_RANGE_BYTES", 4096)  # let small files split
        raw, workers, overlap = data.draw(seam_layouts(), label="layout")
        tmp = tmp_path_factory.mktemp("fz_par")
        probe = tmp / "probe.bin"
        probe.write_bytes(bytes(raw))
        seams = par.plan_ranges(str(probe), workers, "utf-8", overlap)[1:-1]
        event(f"seams={len(seams)}")
        for seam in seams:
            for _ in range(data.draw(st.integers(1, 2), label="entities_per_seam")):
                e = data.draw(entities, label="entity").encode()
                cut = data.draw(st.integers(1, max(1, len(e) - 1)), label="cut")
                pos = max(0, min(seam - cut, len(raw) - len(e) - 1))
                raw[pos : pos + len(e)] = e
            if data.draw(st.booleans(), label="poison"):
                # undecodable / multi-byte debris right on the seam
                junk = data.draw(
                    st.sampled_from(
                        [b"\xff", b"\xe6\x96", "文".encode(), "𝕏".encode(), b"\x00", b"\r"]
                    ),
                    label="junk",
                )
                raw[seam : seam + len(junk)] = junk
        blob = bytes(raw)
        r = make_redactor(overlap, 1024, backend)
        in_contract(r, blob)
        want = whole(r, blob)
        got, outcome = parallel(r, blob, workers, tmp)
        event(f"ranges={outcome.ranges}")
        event(f"fallback_reason={outcome.fallback_reason}")
        assert_identical(
            "parallel",
            got,
            want,
            workers=workers,
            overlap=overlap,
            ranges=outcome.ranges,
            fell_back=outcome.fallback_reason,
        )


def test_fuzzer_detects_a_planted_boundary_bug():
    """Mutation check: the harness must actually be able to fail.

    A redactor whose emit boundary ignores straddling detections (simulated by a
    detector that only sees a window half the size it needs) must be caught --
    otherwise a green run proves nothing.
    """
    r = make_redactor(overlap=128, chunk_size=1, backend="python")
    email = "alice@corp.example.com"
    text = "x" * 120 + email + "y" * 120
    # honest run is identical ...
    assert streaming(r, text.encode(), [1]) == whole(r, text.encode())
    # ... a sabotaged overlap (1) with the strict guard off leaks the straddler
    bad = make_redactor(overlap=1, chunk_size=1, backend="python")
    leaked = streaming(bad, text.encode(), [1])
    with pytest.raises(AssertionError, match="EQUIVALENCE VIOLATED"):
        assert_identical("stream", leaked, whole(r, text.encode()))
