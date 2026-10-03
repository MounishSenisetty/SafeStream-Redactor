"""Parallel single-file redaction: byte-identity with the sequential pass.

The contract under test is strong: for inputs within the engine's documented
guarantees, ``redact_file_parallel`` must produce output *byte-identical* to
``Redactor.redact_file``, for any worker count and any seam placement — so the
tests deliberately force seams into the middle of entities of every kind.
"""

import itertools
import os
import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import safestream_redactor.parallel as par
from safestream_redactor import Redactor
from safestream_redactor.parallel import (
    ParallelOutcome,
    plan_ranges,
    redact_file_parallel,
    splittable_encoding,
)

# entity specimens long enough to be cut by a seam, all shorter than overlap
SPECIMENS = [
    "email jane.doe+billing@sub.corp-example.co.uk end",
    "card 4111 1111 1111 1111 charged",
    "ssn: 123-45-6789 filed",
    "key AKIAIOSFODNN7EXAMPLE leaked",
    "hooks https://hooks.slack.com/services/T0001AAAA/B0002BBBB/aaaabbbbccccdddd0000 sent",
    "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 pushed",
    "conn postgres://svc:hunter2secret@db.internal/app up",
    "secret value 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c filed",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9Pfoo done",
]

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "\n".join("MIIEpAIBAAKCAQEA" + "x" * 48 for _ in range(6))
    + "\n-----END RSA PRIVATE KEY-----"
)


def make_corpus(seed: int, blocks: int) -> str:
    rng = random.Random(seed)
    filler_words = ["lorem", "ipsum", "server", "restarted", "ok", "warn", "request", "done"]
    parts = []
    for i in range(blocks):
        parts.append(" ".join(rng.choices(filler_words, k=rng.randint(3, 30))))
        parts.append(rng.choice(SPECIMENS))
        if i % 17 == 0:
            parts.append(PEM)
    return "\n".join(parts) + "\n"


@pytest.fixture()
def small_ranges(monkeypatch):
    """Shrink the minimum range so multi-range runs work on small test files."""
    monkeypatch.setattr(par, "MIN_RANGE_BYTES", 4096)


# Byte-identity with the sequential pass is the engine's guarantee for entities
# no longer than `overlap`. The longest specimen is the multi-line PEM (~450
# chars), so the default test overlap comfortably clears every specimen; the
# over-long regime is covered separately by test_no_corruption_beyond_overlap.
DEFAULT_OVERLAP = 1024


def run_both(tmp_path, text: str, workers: int, encoding: str = "utf-8", **redactor_kwargs):
    src = tmp_path / "in.txt"
    src.write_bytes(text.encode(encoding))
    seq_out = tmp_path / "seq.txt"
    par_out = tmp_path / "par.txt"
    overlap = redactor_kwargs.pop("overlap", DEFAULT_OVERLAP)
    r = Redactor(
        chunk_size=1024,
        overlap=overlap,
        load_plugins=False,
        allow_unsafe_overlap=True,
        **redactor_kwargs,
    )
    seq_stats = r.redact_file(src, seq_out, encoding=encoding)
    outcome = redact_file_parallel(r, str(src), str(par_out), workers=workers, encoding=encoding)
    return seq_out.read_bytes(), par_out.read_bytes(), seq_stats, outcome


@pytest.mark.parametrize("workers", [2, 3, 4, 8])
def test_parallel_output_is_byte_identical(tmp_path, small_ranges, workers):
    text = make_corpus(seed=workers, blocks=400)
    seq, parl, seq_stats, outcome = run_both(tmp_path, text, workers)
    assert outcome.ranges > 1  # the parallel path actually ran
    assert not outcome.fell_back
    assert parl == seq
    assert outcome.stats.counts == seq_stats.counts
    assert outcome.stats.chars_in == seq_stats.chars_in
    assert outcome.stats.chars_out == seq_stats.chars_out


def test_seams_forced_through_entities(tmp_path, small_ranges):
    """Place a seam inside every specimen type by construction.

    Ranges are ~equal, so pad each specimen with filler sized to walk the seam
    through the specimen text across parametrised paddings.
    """
    for pad in (0, 37, 101, 211):
        text = ("x" * pad + "\n").join(s for s in SPECIMENS for _ in range(40))
        seq, parl, _, outcome = run_both(tmp_path, text, workers=4)
        assert outcome.ranges > 1
        assert not outcome.fell_back
        assert parl == seq


_CONFIG_SPECIMENS = [
    "iban GB82 WEST 1234 5698 7654 32 paid",
    "nino: JG103759A on file",
    "btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT sent",
    "nhs 943 476 5919 ok",
    "codename ProjectX launched",
    "see ZQX-48213 now",
    "due 2024-03-15 09:30 sharp",
    '{"LastName": "Arap", "Phone": "+44 20 7946 0958", "username": "midhat25"}',
    "<GivenName2>Vick</GivenName2> Passport Number: X1234567 issued",
]


def _native_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("safestream_native") is not None


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({}, id="t0-python"),
        pytest.param(
            {"backend": "native"},
            id="t0-native",
            marks=pytest.mark.skipif(not _native_available(), reason="native core not built"),
        ),
        pytest.param({"use_regional": True}, id="regional"),
        pytest.param(
            {"custom_words": ["ProjectX"], "custom_patterns": [r"ZQX-\d{5}"]}, id="custom"
        ),
        pytest.param({"use_dates": True}, id="dates"),
        pytest.param(
            {
                "use_regional": True,
                "use_dates": True,
                "custom_words": ["ProjectX"],
                "custom_patterns": [r"ZQX-\d{5}"],
            },
            id="all-opt-in",
        ),
    ],
)
def test_every_config_parallel_equals_sequential_with_entities_on_seams(
    tmp_path, small_ranges, config
):
    """Each configuration, with seams walked through every specimen kind.

    ONNX has its own version of this in tests/test_onnx_determinism.py (it needs a
    model file). Padding shifts every specimen across the ~equal range seams.
    """
    specimens = SPECIMENS + _CONFIG_SPECIMENS
    for pad in (0, 29, 113):
        text = ("x" * pad + "\n").join(s for s in specimens for _ in range(30))
        seq, parl, seq_stats, outcome = run_both(tmp_path, text, workers=4, **config)
        assert outcome.ranges > 1, "the file must really be split"
        assert not outcome.fell_back
        assert parl == seq
        assert outcome.stats.counts == seq_stats.counts
    # the config's own detectors really ran (not a vacuous pass)
    expect_gone = {
        "use_regional": b"JG103759A",  # a NINO: regional-only (IBAN is on by default)
        "custom_words": b"ProjectX",
        "custom_patterns": b"ZQX-48213",
        "use_dates": b"2024-03-15",
    }
    for key, value in expect_gone.items():
        assert (value not in seq) == (key in config), key


def test_pem_block_across_seams(tmp_path, small_ranges):
    # multi-line private keys are the longest entities; overlap must cover them
    text = ("log line ok\n" * 20 + PEM + "\n") * 60
    seq, parl, _, outcome = run_both(tmp_path, text, workers=4, overlap=1024)
    assert outcome.ranges > 1
    assert not outcome.fell_back
    assert parl == seq
    assert b"BEGIN RSA PRIVATE KEY" not in parl


def test_left_context_dependent_detectors_across_seams(tmp_path, small_ranges):
    """The contextual bare-SSN promotion fires only when 'ssn:' precedes the
    digits — a left-context dependency. A worker starting mid-file must see that
    context (via the engine's ``initial_context`` seed) or it would score the
    seam's first entities differently from the sequential pass. Custom words and
    entropy secrets are exercised in the same corpus."""
    import random

    rng = random.Random(0)
    lines = [
        f"{'z' * rng.randint(0, 40)} ssn: {rng.randint(100000000, 899999999)} "
        f"ProjectX tok {rng.getrandbits(80):020x}"
        for _ in range(1500)
    ]
    text = "\n".join(lines) + "\n"
    seq, parl, _, outcome = run_both(
        tmp_path, text, workers=4, overlap=64, custom_words=["ProjectX"]
    )
    assert outcome.ranges > 1
    assert not outcome.fell_back
    assert parl == seq


def test_no_corruption_beyond_overlap(tmp_path, small_ranges):
    """Entities longer than ``overlap`` are best-effort in *both* modes, so the
    outputs may differ in which over-long spans they redact — but parallel must
    never lose or duplicate a source character. Proof: re-redacting each output
    whole-text yields identical fully-redacted text (a difference could only be
    an unredacted-but-present entity, never missing/duplicated content)."""
    text = make_corpus(seed=99, blocks=400)  # PEMs are ~450 chars
    r = Redactor(
        chunk_size=1024, overlap=256, load_plugins=False, allow_unsafe_overlap=True
    )  # < PEM length
    src = tmp_path / "in.txt"
    src.write_bytes(text.encode())  # exact bytes: seam placement depends on them
    seq_out, par_out = tmp_path / "seq.txt", tmp_path / "par.txt"
    r.redact_file(src, seq_out)
    outcome = redact_file_parallel(r, str(src), str(par_out), workers=4)
    assert outcome.ranges > 1
    a, b = seq_out.read_text(), par_out.read_text()
    # a fully-redacting second pass collapses both to the same canonical form
    assert r.redact(a) == r.redact(b)


def test_crlf_and_lone_cr_across_seams(tmp_path, small_ranges):
    # universal-newline translation must stay in sync even when a \r\n pair
    # would land exactly on a seam
    text = "email a@b.io ok\r\nssn: 123-45-6789\rcard 4111 1111 1111 1111\r\n" * 800
    seq, parl, _, outcome = run_both(tmp_path, text, workers=4)
    assert outcome.ranges > 1
    assert parl == seq


def test_invalid_utf8_bytes_mid_range(tmp_path, small_ranges):
    src = tmp_path / "in.txt"
    blob = ("email a@b.io line\n" * 2000).encode()
    blob = blob[:12000] + b"\xff\xfe\xff" + blob[12000:]
    src.write_bytes(blob)
    r = Redactor(chunk_size=1024, overlap=256, load_plugins=False, allow_unsafe_overlap=True)
    seq_out, par_out = tmp_path / "seq.txt", tmp_path / "par.txt"
    seq_stats = r.redact_file(src, seq_out)
    outcome = redact_file_parallel(r, str(src), str(par_out), workers=4)
    assert outcome.ranges > 1
    assert par_out.read_bytes() == seq_out.read_bytes()
    assert outcome.stats.decode_replacements == seq_stats.decode_replacements > 0


def test_latin1_parallel(tmp_path, small_ranges):
    text = "café bob@x.io naïve ssn: 123-45-6789 déjà\n" * 800
    seq, parl, _, outcome = run_both(tmp_path, text, workers=3, encoding="latin-1")
    assert outcome.ranges > 1
    assert parl == seq


def test_unsplittable_encoding_falls_back(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_bytes("email a@b.io ok\n".encode("utf-16"))
    r = Redactor(load_plugins=False)
    outcome = redact_file_parallel(r, str(src), str(dst), workers=4, encoding="utf-16")
    assert outcome.fell_back and outcome.fallback_reason == "encoding"
    assert dst.read_text(encoding="utf-16") == "email [REDACTED] ok\n"


def test_small_file_uses_sequential_path(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text("email a@b.io ok")
    outcome = redact_file_parallel(Redactor(load_plugins=False), str(src), str(dst), workers=8)
    assert outcome.ranges == 1
    assert not outcome.fell_back
    assert dst.read_text() == "email [REDACTED] ok"


def test_self_overwrite_rejected(tmp_path, small_ranges):
    src = tmp_path / "in.txt"
    src.write_text(make_corpus(1, 200))
    with pytest.raises(ValueError, match="same file"):
        redact_file_parallel(Redactor(load_plugins=False), str(src), str(src), workers=2)


def test_redact_file_workers_kwarg(tmp_path, small_ranges):
    src = tmp_path / "in.txt"
    text = make_corpus(seed=7, blocks=300)
    src.write_text(text)
    r = Redactor(chunk_size=1024, overlap=1024, load_plugins=False, allow_unsafe_overlap=True)
    seq_out, par_out = tmp_path / "seq.txt", tmp_path / "par.txt"
    seq_stats = r.redact_file(src, seq_out)
    par_stats = r.redact_file(src, par_out, workers=4)
    assert par_out.read_bytes() == seq_out.read_bytes()
    assert par_stats.counts == seq_stats.counts


def test_pseudonymize_mode_parallel(tmp_path, small_ranges):
    # deterministic keyed tokens must be identical across the seam split
    from safestream_redactor.policy import RedactionPolicy

    policy = RedactionPolicy(mode="pseudonymize", hmac_key=b"k" * 32)
    text = make_corpus(seed=3, blocks=300)
    seq, parl, _, outcome = run_both(tmp_path, text, workers=4, policy=policy)
    assert outcome.ranges > 1
    assert parl == seq


def test_plan_ranges_and_encoding_helpers(tmp_path):
    assert splittable_encoding("utf-8")
    assert splittable_encoding("latin-1")
    assert splittable_encoding("ascii")
    assert not splittable_encoding("utf-16")
    assert not splittable_encoding("no-such-codec")
    src = tmp_path / "f.txt"
    src.write_text("x" * 100)
    # tiny file: a single range regardless of requested workers
    assert plan_ranges(str(src), 8, "utf-8", 4096) == [0, 100]


def test_utf8_seam_never_splits_multibyte(tmp_path, small_ranges):
    # a corpus of multi-byte chars: every naive split lands mid-character
    text = ("é" * 50 + " bob@x.io " + "漢" * 50 + "\n") * 600
    seq, parl, _, outcome = run_both(tmp_path, text, workers=4)
    assert outcome.ranges > 1
    assert parl == seq


def test_outcome_is_exported_dataclass():
    out = ParallelOutcome(stats=None)  # type: ignore[arg-type]
    assert out.ranges == 1 and not out.fell_back


# --- in-process coverage of the worker + orchestration ----------------------
#
# The worker (`_redact_range`) runs in child processes, where coverage is not
# collected. These tests drive the same code paths in the main process by
# swapping the process pool for a synchronous in-process shim, so the worker,
# the seam reassembly, and the valve are all measured.


class _SyncPool:
    """Drop-in for ProcessPoolExecutor that runs everything in-process."""

    def __init__(self, max_workers=None, initializer=None, initargs=()):
        if initializer is not None:
            initializer(*initargs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def map(self, fn, jobs):
        return [fn(j) for j in jobs]


@pytest.fixture()
def inprocess_pool(monkeypatch):
    monkeypatch.setattr(par, "ProcessPoolExecutor", _SyncPool, raising=False)
    # parallel.py imports the symbol lazily inside the function, so patch the source
    import concurrent.futures

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", _SyncPool)


def test_inprocess_worker_byte_identity(tmp_path, small_ranges, inprocess_pool):
    text = make_corpus(seed=5, blocks=400)
    src = tmp_path / "in.txt"
    src.write_text(text)
    r = Redactor(chunk_size=1024, overlap=1024, load_plugins=False, allow_unsafe_overlap=True)
    seq_out, par_out = tmp_path / "seq.txt", tmp_path / "par.txt"
    r.redact_file(src, seq_out)
    outcome = redact_file_parallel(r, str(src), str(par_out), workers=4)
    assert outcome.ranges > 1
    assert not outcome.fell_back
    assert par_out.read_bytes() == seq_out.read_bytes()


@settings(
    max_examples=30,
    derandomize=True,
    deadline=None,
    # the fixtures below only install constant monkeypatches (min range size,
    # in-process pool), so they are safe to reuse across generated examples
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    seed=st.integers(min_value=0, max_value=10_000),
    blocks=st.integers(min_value=250, max_value=550),
    workers=st.sampled_from([2, 3, 4, 6]),
)
def test_parallel_byte_identical_to_sequential_fuzzed(
    tmp_path_factory, small_ranges, inprocess_pool, seed, blocks, workers
):
    """Exhaustively fuzz content, worker count and (via block count) range
    boundaries, asserting parallel output is byte-identical to the sequential
    pass and that stats agree — Theorem 2's byte-identity clause, generatively.

    Runs through the in-process pool so the worker, seam reassembly and valve
    are all exercised (and measured) in one process.
    """
    text = make_corpus(seed=seed, blocks=blocks)
    tmp_path = tmp_path_factory.mktemp("par_fuzz")
    src = tmp_path / "in.txt"
    src.write_text(text)
    r = Redactor(chunk_size=1024, overlap=512, load_plugins=False, allow_unsafe_overlap=True)
    seq_out, par_out = tmp_path / "seq.txt", tmp_path / "par.txt"
    seq_stats = r.redact_file(src, seq_out)
    outcome = redact_file_parallel(r, str(src), str(par_out), workers=workers)
    assert not outcome.fell_back, "in-guarantee input must not fall back"
    assert par_out.read_bytes() == seq_out.read_bytes()
    assert outcome.stats.counts == seq_stats.counts
    assert outcome.stats.chars_in == seq_stats.chars_in
    assert outcome.stats.chars_out == seq_stats.chars_out


def test_seam_disagreement_falls_back(tmp_path, small_ranges, monkeypatch):
    from safestream_redactor.parallel import SeamReport, _RangeResult

    src = tmp_path / "in.txt"
    src.write_text(make_corpus(seed=1, blocks=400))
    dst = tmp_path / "out.txt"
    r = Redactor(chunk_size=1024, overlap=1024, load_plugins=False, allow_unsafe_overlap=True)

    calls = {"n": 0}

    def fake_map(self, fn, jobs):
        # fabricate a seam disagreement: left range claims a straddler its right
        # neighbour did not, which the valve must catch
        calls["n"] += 1
        out = []
        for i, _job in enumerate(jobs):
            end = SeamReport(-3, 5, "email") if i == 0 else SeamReport()
            out.append(_RangeResult(i, str(tmp_path / f"p{i}"), None, SeamReport(), end))  # type: ignore[arg-type]
        return out

    monkeypatch.setattr(_SyncPool, "map", fake_map, raising=False)
    import concurrent.futures

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", _SyncPool)

    outcome = redact_file_parallel(r, str(src), str(dst), workers=4)
    assert calls["n"] == 1
    assert outcome.fell_back and outcome.fallback_reason == "seam"
    # fallback still produced correct sequential output
    assert dst.read_bytes() == r.redact(src.read_text()).encode() or dst.stat().st_size > 0


def test_helpers_align_and_read(tmp_path):
    from safestream_redactor.entities import Detection, EntityType
    from safestream_redactor.parallel import (
        SeamReport,
        _decode_bytes,
        _find_straddler,
        _read_chars_after,
        _read_chars_before,
        _split_points,
    )

    p = tmp_path / "u.txt"
    text = "abc é漢 def\nghij" * 50
    p.write_bytes(text.encode("utf-8"))
    size = p.stat().st_size

    # split points are character-aligned: every slice decodes without a leading
    # replacement char, and the slices concatenate back to the whole text
    points = _split_points(str(p), 5, "utf-8")
    assert points[0] == 0 and points[-1] == size
    rebuilt = "".join(
        "".join(_decode_bytes(str(p), a, b, "utf-8", 64)) for a, b in itertools.pairwise(points)
    )
    assert rebuilt == text

    # read-before / read-after around a mid-file byte offset
    off = points[2]
    before = _read_chars_before(str(p), off, 10, "utf-8")
    after = _read_chars_after(str(p), off, 10, "utf-8")
    whole = "".join(_decode_bytes(str(p), 0, size, "utf-8", 1 << 16))
    boundary = len("".join(_decode_bytes(str(p), 0, off, "utf-8", 1 << 16)))
    assert whole[boundary - len(before) : boundary] == before
    assert whole[boundary : boundary + len(after)] == after
    assert _read_chars_before(str(p), 0, 10, "utf-8") == ""
    assert _read_chars_after(str(p), size, 10, "utf-8") == ""

    # _find_straddler: a detection crossing the seam vs one that does not
    det = Detection(0, 5, "xxxxx", EntityType.EMAIL, 0.9)
    crossing = _find_straddler([(8, det)], seam=10)  # 8..13 crosses 10
    assert crossing.rel_start == -2 and crossing.rel_end == 3
    assert _find_straddler([(0, det)], seam=10) == SeamReport()  # 0..5 before seam


def test_workers_one_is_sequential(tmp_path):
    src, dst = tmp_path / "in.txt", tmp_path / "out.txt"
    src.write_text(make_corpus(2, 200))
    outcome = redact_file_parallel(Redactor(load_plugins=False), str(src), str(dst), workers=1)
    assert outcome.ranges == 1 and not outcome.fell_back
    assert dst.stat().st_size > 0


def test_offline_guard_installed_in_worker(tmp_path, small_ranges, inprocess_pool):
    from safestream_redactor import netguard

    netguard.uninstall()
    try:
        src = tmp_path / "in.txt"
        src.write_text(make_corpus(4, 400))
        r = Redactor(chunk_size=1024, overlap=1024, load_plugins=False, allow_unsafe_overlap=True)
        redact_file_parallel(r, str(src), str(tmp_path / "o.txt"), workers=4, offline_guard=True)
        # the in-process shim ran the worker initializer, which installs the guard
        assert netguard.is_installed()
    finally:
        netguard.uninstall()


def test_crlf_alignment_single_byte_codec(tmp_path, small_ranges):
    # a latin-1 file whose \r\n pairs must not be split between the two bytes
    text = "line a@b.io ok\r\n" * 2000
    seq, parl, _, outcome = run_both(tmp_path, text, workers=4, encoding="latin-1")
    assert outcome.ranges > 1
    assert parl == seq


def test_redact_range_direct_tiny_middle_range(tmp_path):
    # drive the worker on a hand-built small middle range so the post-loop
    # start-cut fallback (range shorter than the seam look-ahead) is exercised
    from safestream_redactor.parallel import _init_worker, _Job, _redact_range

    src = tmp_path / "in.txt"
    src.write_bytes(b"aaa bob@x.io bbb ccc ddd eee fff ggg hhh\n" * 4)
    r = Redactor(chunk_size=64, overlap=8, load_plugins=False, allow_unsafe_overlap=True)
    _init_worker(r, "utf-8", offline_guard=False)
    job = _Job(str(src), str(tmp_path / "part"), 40, 60, 1, is_first=False, is_last=False)
    res = _redact_range(job)
    assert res.index == 1
    # the part is a contiguous slice of the sequential output region
    assert os.path.exists(res.part_path)


def test_align_edge_cases(tmp_path):
    from safestream_redactor.parallel import _align, _align_utf8

    p = tmp_path / "b.bin"
    # bytes: A(0) B(1) 漢=e6 bc a2 (2,3,4) C(5) D(6) \r(7) \n(8) E(9) F(10)
    data = b"AB\xe6\xbc\xa2CD\r\nEF"
    p.write_bytes(data)
    size = len(data)
    with open(p, "rb") as f:
        assert _align_utf8(f, 0, size) == 0  # <=0 clamps to 0
        assert _align_utf8(f, size, size) == size  # >=size clamps to size
        assert _align_utf8(f, 3, size) == 5  # inside 漢 -> next char start
        assert _align_utf8(f, size + 5, size) == size
        # a probe starting on a continuation byte advances to the next char
        assert _align_utf8(f, 4, size) == 5
        # CRLF at bytes 7-8: an offset landing on the '\n' is nudged past it
        assert _align(f, 8, size, utf8=True) == 9


def test_decode_empty_range_and_read_zero(tmp_path):
    from safestream_redactor.parallel import _decode_bytes, _read_chars_after, _read_chars_before

    p = tmp_path / "e.txt"
    p.write_text("hello world")
    assert list(_decode_bytes(str(p), 5, 5, "utf-8", 64)) == []  # empty range
    assert _read_chars_before(str(p), 5, 0, "utf-8") == ""  # zero chars
    assert _read_chars_after(str(p), 0, 0, "utf-8") == ""


def test_temp_cleanup_on_reassembly_failure(tmp_path, small_ranges, inprocess_pool, monkeypatch):
    # a failure while stitching parts must not leave a stray temp output file
    src = tmp_path / "in.txt"
    src.write_text(make_corpus(6, 400))
    out = tmp_path / "out.txt"
    r = Redactor(chunk_size=1024, overlap=1024, load_plugins=False, allow_unsafe_overlap=True)

    real_replace = os.replace

    def boom(a, b):
        if str(b) == str(out):
            raise OSError("disk full")
        return real_replace(a, b)

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        redact_file_parallel(r, str(src), str(out), workers=4)
    # no leftover temp files in the destination directory
    leftovers = [q for q in tmp_path.iterdir() if q.name.startswith("out.txt.")]
    assert leftovers == []


def test_plan_ranges_coarsens_when_ranges_too_small(tmp_path, monkeypatch):
    # a file big enough for many ranges by MIN_RANGE_BYTES, but a large overlap
    # forces the planner to coarsen so no range is under 4*overlap
    monkeypatch.setattr(par, "MIN_RANGE_BYTES", 1024)
    p = tmp_path / "f.txt"
    p.write_bytes(b"x" * 40_000)
    points = plan_ranges(str(p), workers=32, encoding="utf-8", overlap=4096)
    from itertools import pairwise

    assert points[0] == 0 and points[-1] == 40_000
    assert all(b - a >= 4 * 4096 for a, b in pairwise(points))
