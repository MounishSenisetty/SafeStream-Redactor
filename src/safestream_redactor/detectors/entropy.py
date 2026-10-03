"""Statistical tier: high-entropy secret detection.

Catches bespoke, undocumented secrets that have no published format (random
API keys, session tokens, generated passwords) by scoring each candidate
token's Shannon entropy. This is the class of secret that pattern-only tools —
and general-purpose PII engines like Presidio — miss entirely, and it is what
dedicated secret scanners (detect-secrets, truffleHog) specialise in.

Precision is kept high by requiring a minimum length, a mixed character set,
and an entropy floor tuned per alphabet (hex strings are inherently
lower-entropy than base64, so they get a lower floor).
"""

from __future__ import annotations

import math
import re
from collections import Counter

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.detectors.deterministic import NativeBacked
from safestream_redactor.entities import Detection, EntityType

# The longest span the entropy tier will emit. Bounding it keeps assumption A1
# (docs/FORMAL_MODEL.md) — every span is at most ``MAX_SPAN`` characters — true
# for this tier, which is otherwise the one detector whose candidate length is
# unbounded. It is set to the default streaming overlap so Theorem 1's premise
# (``overlap >= L_max``) holds at the default configuration.
MAX_SPAN = 8 * 1024

# A candidate is a run of secret-looking characters bounded by non-secret chars.
# The length is capped at ``MAX_SPAN``; a run longer than that is matched as
# consecutive capped spans (no lookbehind/lookahead, so the tail is never
# dropped) rather than one unbounded span. For every run up to ``MAX_SPAN`` the
# match is identical to an unbounded candidate — a differential test pins this —
# so the cap changes behaviour only for runs longer than the streaming overlap,
# which are outside the engine's single-span guarantee anyway.
_CANDIDATE = re.compile(rf"[A-Za-z0-9+/=_-]{{20,{MAX_SPAN}}}")
_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")
_ALPHA_ONLY = re.compile(r"\A[A-Za-z]+\Z")

# High-entropy shapes that are identifiers, not secrets (a UUID, a commit or
# content digest, an inline image). Dropped unless a secret-like key precedes
# the value on its line: ``API_KEY=6f1c…-…`` is a key whatever its shape.
# The checks read at most ``_CONTEXT`` characters to the left of a token, which
# the tier declares to the streaming engine, so streaming output still equals
# whole-text output.
_CONTEXT = 80
_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_DIGEST_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})  # md5, sha1, sha224 ... sha512
_HASH_CONTEXT = re.compile(
    r"(?i)\b(?:commit|sha(?:1|224|256|384|512)?|md5|digest|checksum|hash|integrity|etag"
    r"|rev(?:ision)?)\b[^\n]{0,16}\Z"
)
_IDENT_KEY = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.-]*\Z")
_DATA_URI = re.compile(r"(?i)\bdata:[\w.+-]+/[\w.+-]+;base64,\Z")
_SECRET_KEY = re.compile(
    r"(?i)(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth"
    r"|credential|private[_-]?key)[^\n]{0,40}\Z"
)


def _identifier_not_secret(text: str, start: int, token: str) -> bool:
    """True for a UUID, a digest after a hash word, or a data-URI payload,
    unless a secret-like key precedes the token on its line."""
    left = text[max(0, start - _CONTEXT) : start]
    left = left[left.rfind("\n") + 1 :]  # this line only
    # ``=`` is in the candidate alphabet (base64 padding), so ``request_id=<uuid>``
    # arrives as one token: judge the value, with the key as context
    key, eq, value = token.partition("=")
    if eq and value and not value.startswith("=") and _IDENT_KEY.match(key):
        left, token = left + key + eq, value
    if _SECRET_KEY.search(left):
        return False
    if _UUID.match(token):
        return True
    if len(token) in _DIGEST_LENGTHS and _HEX.match(token) and _HASH_CONTEXT.search(left):
        return True
    return bool(_DATA_URI.search(left))


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for uniform, up to log2(alphabet))."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyDetector(NativeBacked):
    """Flags high-entropy tokens as generic secrets.

    Named-credential patterns (tier 1) score higher, so when a token is both a
    recognised credential and high-entropy, overlap resolution keeps the more
    specific label.
    """

    name = "entropy"
    # A candidate run is capped at MAX_SPAN characters (see _CANDIDATE), so that
    # is the longest span this tier can emit; the identifier check reads
    # _CONTEXT characters before each candidate.
    requirements = StreamingRequirements(max_span=MAX_SPAN, left_context=_CONTEXT)

    def __init__(
        self,
        min_length: int = 24,
        base64_entropy: float = 4.0,
        hex_entropy: float = 3.0,
        confidence: float = 0.6,
        backend: str = "python",
    ) -> None:
        self.min_length = min_length
        self.base64_entropy = base64_entropy
        self.hex_entropy = hex_entropy
        self.confidence = confidence
        # optional native core: same candidates, same verdicts; tokens whose
        # entropy is within 1e-9 of a threshold come back undecided and are
        # classified here (native/src/secrets.rs explains the bound)
        self._attach_native(backend)

    def _secret_entropy(self, token: str) -> float | None:
        """The token's Shannon entropy if it qualifies as a secret, else ``None``.

        Returns the computed entropy so callers reuse it (for the detection's
        ``meta``) instead of recomputing it — it is the one non-trivial cost on
        the hot path and was previously calculated twice per emitted secret.
        """
        if len(token) < self.min_length:
            return None
        # a run of only letters is almost always prose/an identifier, not a secret
        if _ALPHA_ONLY.match(token):
            return None
        entropy = shannon_entropy(token)
        if _HEX.match(token):
            return entropy if (len(token) >= 32 and entropy >= self.hex_entropy) else None
        return entropy if entropy >= self.base64_entropy else None

    def detect(self, text: str) -> list[Detection]:
        if self._native is not None:  # pragma: no cover - requires native extension
            native = self._detect_native(text)
            if native is not None:
                return native
        found: list[Detection] = []
        for m in _CANDIDATE.finditer(text):
            token = m.group()
            entropy = self._secret_entropy(token)
            if entropy is not None and not _identifier_not_secret(text, m.start(), token):
                found.append(self._detection(m.start(), m.end(), token, entropy))
        return found

    def _detection(self, start: int, end: int, token: str, entropy: float) -> Detection:
        return Detection(
            start=start,
            end=end,
            text=token,
            entity_type=EntityType.SECRET,
            confidence=self.confidence,
            source=self.name,
            meta={"entropy": f"{entropy:.2f}"},
        )

    def _detect_native(self, text: str) -> list[Detection] | None:  # pragma: no cover
        runs = self._native_call(
            self._native.scan_entropy_text,
            text,
            self.min_length,
            self.base64_entropy,
            self.hex_entropy,
        )
        if runs is None:
            return None  # a lone surrogate: the caller scans in Python
        found: list[Detection] = []
        for start, end, native_entropy, decided in runs:
            token = text[start:end]
            entropy = native_entropy if decided else self._secret_entropy(token)
            # the identifier check is shared Python code, so both backends agree
            if entropy is not None and not _identifier_not_secret(text, start, token):
                found.append(self._detection(start, end, token, entropy))
        return found


# --- compound (symbol-containing) secret tier ------------------------------
#
# The entropy candidate above stops at the first character outside the base64
# alphabet, so a password with an embedded "strong" special
# (``devPass_pP0p18yO3n!vT8wZ``) splits into sub-tokens that each fall below the
# length/entropy floor and is missed entirely — the documented cause-#4 gap in
# ``benchmarks/redactionbench/AUDIT.md``. This tier closes it *without* lowering
# the entropy tier's precision: it only fires on a whitespace-free run that
# carries a strong password special (``! # $ % ^ & * ~``) embedded *between*
# alphanumerics — a shape natural-language prose, URLs, e-mail addresses, file
# paths and base64/hex blobs do not produce — and additionally requires
# character-class diversity and an entropy floor.
#
# Deliberately excluded from the run alphabet: ``@ . ? & = :`` and the ``/``
# scheme separator, because they are exactly what makes URLs, hosts and e-mail
# addresses look "secret-shaped"; only ``+ / = _ -`` (base64) plus the strong
# specials are admitted. The strong-special *gate* never counts a base64/URL
# character, so a bare URL, host, path or base64 string can never trip this tier.
#
# Span length is bounded to ``MAX_SPAN`` (same as the entropy tier), so
# assumption A1 (docs/FORMAL_MODEL.md) is preserved and no change to the
# engine's overlap or the audited constants is required.

# strong password specials that base64, hex, URLs and e-mail addresses do not use
_STRONG_SPECIALS = frozenset("!#$%^&*~")
# run alphabet: base64/identifier chars plus the strong specials (no @ . ? & = :)
_COMPOUND_CANDIDATE = re.compile(rf"[A-Za-z0-9+/=_\-!#$%^&*~]{{20,{MAX_SPAN}}}")


class CompoundSecretDetector(NativeBacked):
    """Flags symbol-containing high-entropy secrets the base entropy tier splits.

    A candidate is a whitespace-free run over the base64 alphabet extended with
    the strong password specials. It is emitted as a generic ``SECRET`` only when
    (1) it contains a strong special *embedded between two alphanumerics*, (2) it
    mixes at least two of {lowercase, uppercase, digit}, (3) its distinct-character
    ratio is high enough to exclude padded/repeated filler, and (4) its Shannon
    entropy clears a floor. Every gate is a function of the candidate token alone,
    so the tier is stateless and window-pure like the entropy tier, and its spans
    are bounded by ``MAX_SPAN`` — the streaming/parallel equivalence guarantees
    and the audited locality constants are unaffected.
    """

    name = "compound_secret"
    requirements = StreamingRequirements(max_span=MAX_SPAN)

    def __init__(
        self,
        min_length: int = 20,
        entropy_floor: float = 3.5,
        distinct_ratio: float = 0.45,
        confidence: float = 0.6,
        backend: str = "python",
    ) -> None:
        self.min_length = min_length
        self.entropy_floor = entropy_floor
        self.distinct_ratio = distinct_ratio
        self.confidence = confidence
        self._attach_native(backend)

    def _is_compound_secret(self, token: str) -> bool:
        n = len(token)
        if n < self.min_length:
            return False
        # (1) a strong special must sit *between* two alphanumerics — the signal
        # that separates a password/blob from prose, a URL, a host or base64.
        if not any(
            token[i] in _STRONG_SPECIALS
            and 0 < i < n - 1
            and token[i - 1].isalnum()
            and token[i + 1].isalnum()
            for i in range(n)
        ):
            return False
        # (2) alphanumeric class diversity (a random blob, not a word + suffix)
        classes = sum(
            (
                any(c.islower() for c in token),
                any(c.isupper() for c in token),
                any(c.isdigit() for c in token),
            )
        )
        if classes < 2:
            return False
        # (3) reject padded/repeated filler (e.g. "aaaaa!bbbbb#ccccc")
        if len(set(token)) / n < self.distinct_ratio:
            return False
        # (4) entropy floor
        return shannon_entropy(token) >= self.entropy_floor

    def detect(self, text: str) -> list[Detection]:
        # Prefilter: a compound secret must contain a strong special embedded
        # between alphanumerics, so if the window has no strong special at all,
        # no candidate can qualify. A cheap C-level substring scan then avoids the
        # regex pass and per-candidate work entirely on secret-sparse input (e.g.
        # long base64/alpha blobs), keeping this tier near-free there. This is an
        # optimisation only: output is identical to running the scan unconditionally
        # (a strong special is a necessary condition in ``_is_compound_secret``).
        if not any(s in text for s in _STRONG_SPECIALS):
            return []
        if self._native is not None:  # pragma: no cover - requires native extension
            native = self._detect_native(text)
            if native is not None:
                return native
        found: list[Detection] = []
        for m in _COMPOUND_CANDIDATE.finditer(text):
            token = m.group()
            if self._is_compound_secret(token):
                found.append(self._detection(m.start(), m.end(), token, shannon_entropy(token)))
        return found

    def _detection(self, start: int, end: int, token: str, entropy: float) -> Detection:
        return Detection(
            start=start,
            end=end,
            text=token,
            entity_type=EntityType.SECRET,
            confidence=self.confidence,
            source=self.name,
            meta={"entropy": f"{entropy:.2f}", "shape": "compound"},
        )

    def _detect_native(self, text: str) -> list[Detection] | None:  # pragma: no cover
        runs = self._native_call(
            self._native.scan_compound_text,
            text,
            self.min_length,
            self.entropy_floor,
            self.distinct_ratio,
        )
        if runs is None:
            return None  # a lone surrogate: the caller scans in Python
        found: list[Detection] = []
        for start, end, native_entropy, decided in runs:
            token = text[start:end]
            if decided:
                found.append(self._detection(start, end, token, native_entropy))
            elif self._is_compound_secret(token):
                found.append(self._detection(start, end, token, shannon_entropy(token)))
        return found
