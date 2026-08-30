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


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0 for uniform, up to log2(alphabet))."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyDetector:
    """Flags high-entropy tokens as generic secrets.

    Named-credential patterns (tier 1) score higher, so when a token is both a
    recognised credential and high-entropy, overlap resolution keeps the more
    specific label.
    """

    name = "entropy"
    # A candidate run is capped at MAX_SPAN characters (see _CANDIDATE), so that
    # is the longest span this tier can emit.
    requirements = StreamingRequirements(max_span=MAX_SPAN)

    def __init__(
        self,
        min_length: int = 24,
        base64_entropy: float = 4.0,
        hex_entropy: float = 3.0,
        confidence: float = 0.6,
    ) -> None:
        self.min_length = min_length
        self.base64_entropy = base64_entropy
        self.hex_entropy = hex_entropy
        self.confidence = confidence

    def _is_secret(self, token: str) -> bool:
        if len(token) < self.min_length:
            return False
        # a run of only letters is almost always prose/an identifier, not a secret
        if _ALPHA_ONLY.match(token):
            return False
        entropy = shannon_entropy(token)
        if _HEX.match(token):
            return len(token) >= 32 and entropy >= self.hex_entropy
        return entropy >= self.base64_entropy

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for m in _CANDIDATE.finditer(text):
            token = m.group()
            if self._is_secret(token):
                found.append(
                    Detection(
                        start=m.start(),
                        end=m.end(),
                        text=token,
                        entity_type=EntityType.SECRET,
                        confidence=self.confidence,
                        source=self.name,
                        meta={"entropy": f"{shannon_entropy(token):.2f}"},
                    )
                )
        return found
