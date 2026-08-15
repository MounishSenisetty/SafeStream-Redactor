"""Tests for the conflict-only arbitration tier."""

from safestream_redactor import EntityType, LLMArbiter, Redactor, RuleArbiter
from safestream_redactor.arbitration import (
    Conflict,
    _clusters,
    _reason,
    _specificity,
    default_prompt,
    find_conflicts,
)
from safestream_redactor.entities import Detection


def det(start, end, etype, conf, *, source="deterministic", context=None):
    d = Detection(start, end, "x" * (end - start), etype, conf, source=source)
    if context:
        d.meta["context"] = context
    return d


# --- conflict detection ---------------------------------------------------


def test_specificity_ordering():
    assert _specificity(det(0, 1, EntityType.SECRET, 0.6)) == 0
    assert _specificity(det(0, 1, EntityType.PERSON, 0.6)) == 1
    assert _specificity(det(0, 1, EntityType.SSN, 0.6)) == 2


def test_clusters_group_overlapping_only():
    a = det(0, 5, EntityType.EMAIL, 0.9)
    b = det(3, 8, EntityType.PHONE, 0.9)  # overlaps a
    c = det(20, 25, EntityType.SSN, 0.9)  # separate
    groups = _clusters([c, a, b])
    assert len(groups) == 2
    assert {id(x) for x in groups[0]} == {id(a), id(b)}
    assert groups[1] == [c]


def test_reason_overlap_borderline_suppressed_none():
    # overlap: two types, near-equal confidence
    assert (
        _reason([det(0, 5, EntityType.EMAIL, 0.9), det(2, 7, EntityType.PHONE, 0.8)], 0.5, 0.15)
        == "overlap"
    )
    # borderline: single candidate near threshold
    assert _reason([det(0, 5, EntityType.PHONE, 0.45)], 0.5, 0.15) == "borderline"
    # suppressed
    assert (
        _reason([det(0, 5, EntityType.EMAIL, 0.9, context="suppressed")], 0.5, 0.15) == "suppressed"
    )
    # none: a lone, clearly-confident, non-suppressed detection
    assert _reason([det(0, 5, EntityType.EMAIL, 0.95)], 0.5, 0.15) is None


def test_find_conflicts_builds_window_and_offset():
    text = "the number is 040 123 4567 over there in the office"
    d = det(text.index("040"), text.index("4567") + 4, EntityType.PHONE, 0.45)
    conflicts = find_conflicts([d], text, min_confidence=0.5, window=8)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.reason == "borderline"
    # window covers the span plus up to 8 chars of real context each side
    assert c.window == text[c.window_offset : c.window_offset + len(c.window)]
    assert "040 123 4567" in c.window


def test_find_conflicts_skips_unambiguous():
    text = "email a@b.com clearly"
    d = det(text.index("a@b.com"), text.index("a@b.com") + 7, EntityType.EMAIL, 0.95)
    assert find_conflicts([d], text, min_confidence=0.5) == []


# --- RuleArbiter ----------------------------------------------------------


def _conflict(cands, text="context window here"):
    start = min(c.start for c in cands)
    end = max(c.end for c in cands)
    return Conflict(start, end, list(cands), text, 0, "overlap")


def test_rule_arbiter_prefers_higher_confidence():
    email = det(0, 5, EntityType.EMAIL, 0.7)
    phone = det(0, 5, EntityType.PHONE, 0.9)
    winner = RuleArbiter().arbitrate(_conflict([email, phone]))
    assert winner is phone and winner.meta["arbiter"] == "rule"


def test_rule_arbiter_specificity_breaks_confidence_ties():
    # equal confidence: a specific/checkable label beats a generic entropy secret
    secret = det(0, 20, EntityType.SECRET, 0.8)
    ssn = det(0, 20, EntityType.SSN, 0.8)
    winner = RuleArbiter().arbitrate(_conflict([secret, ssn]))
    assert winner is ssn


def test_rule_arbiter_prefers_non_suppressed():
    strong_suppressed = det(0, 5, EntityType.EMAIL, 0.9, context="suppressed")
    weak_live = det(0, 5, EntityType.PHONE, 0.6)
    winner = RuleArbiter().arbitrate(_conflict([strong_suppressed, weak_live]))
    assert winner is weak_live


def test_rule_arbiter_drops_suppressed_and_weak():
    only = det(0, 5, EntityType.EMAIL, 0.3, context="suppressed")
    assert RuleArbiter(min_confidence=0.5).arbitrate(_conflict([only])) is None


# --- prompt + parsing -----------------------------------------------------


def test_default_prompt_marks_span_and_lists_candidates():
    c = _conflict([det(4, 9, EntityType.PHONE, 0.45)], text="say 12345 please")
    prompt = default_prompt(c)
    assert "«12345»" in prompt
    assert "type=phone" in prompt
    assert "DROP" in prompt


def _rule(reply, cands=None):
    cands = cands or [det(0, 5, EntityType.PHONE, 0.45)]
    return LLMArbiter(client=lambda p: reply).arbitrate(_conflict(cands))


def test_llm_arbiter_keep_drop_retype_and_fallbacks():
    assert _rule("DROP") is None

    keep = _rule("KEEP 0")
    assert keep is not None and keep.meta["arbiter"] == "llm"

    assert _rule("KEEP 0 ssn").entity_type is EntityType.SSN
    # unknown type name is ignored, label kept
    assert _rule("KEEP 0 not_a_type").entity_type is EntityType.PHONE

    # garbage reply -> keep strongest as a safety fallback
    fb = _rule("maybe?", [det(0, 5, EntityType.PHONE, 0.4), det(0, 5, EntityType.EMAIL, 0.6)])
    assert fb.entity_type is EntityType.EMAIL and fb.meta["arbiter"] == "llm-fallback"

    # index out of range -> fallback; empty reply -> fallback
    assert _rule("KEEP 9") is not None
    assert _rule("") is not None


def test_llm_arbiter_client_error_uses_deterministic_fallback():
    def boom(prompt):
        raise RuntimeError("model unavailable")

    winner = LLMArbiter(client=boom).arbitrate(_conflict([det(0, 5, EntityType.PHONE, 0.6)]))
    assert winner is not None and winner.meta["arbiter"] == "rule"


# --- Redactor integration -------------------------------------------------


def test_redactor_without_conflicts_is_untouched_by_arbiter():
    # a clearly-confident email is not a conflict, so the arbiter never fires
    calls = []
    spy = LLMArbiter(client=lambda p: calls.append(p) or "DROP")
    # a domain without a suppress trigger ("example"/"test"/…) so nothing is a conflict
    out = Redactor(arbiter=spy).detect("mail bob@corp.io please")
    assert calls == []  # arbiter not consulted
    assert any(d.entity_type is EntityType.EMAIL for d in out)


def test_redactor_rule_arbiter_rescues_borderline_detection():
    text = "reception 040 123 4567 desk"  # bare phone ~0.45, dropped by default
    assert Redactor().detect(text) == []
    kept = Redactor(arbiter=RuleArbiter()).detect(text)
    assert [d.entity_type for d in kept] == [EntityType.PHONE]
    assert kept[0].confidence >= 0.5  # promoted so the ruling survives the threshold


def test_redactor_llm_drop_removes_a_borderline_detection():
    text = "reception 040 123 4567 desk"
    assert Redactor(arbiter=LLMArbiter(client=lambda p: "DROP")).detect(text) == []


def test_rule_arbiter_preserves_streaming_equivalence():
    # the deterministic arbiter reads only candidate-local fields, so streamed
    # redaction must still equal whole-text redaction for any chunking
    text = "reception 040 123 4567 desk; ssn: 123-45-6789; mail a@b.io\n" * 4
    r = Redactor(arbiter=RuleArbiter())

    def chunked(s, n):
        for i in range(0, len(s), n):
            yield s[i : i + n]

    for size in (1, 7, 32, 128):
        assert "".join(r.redact_stream(chunked(text, size))) == r.redact(text), size
