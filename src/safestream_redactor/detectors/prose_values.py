"""Prose-profile tier: years, money amounts and slash-form reference numbers.

In documents (court rulings, letters, case files) a bare year ("born in 1954"),
a sum of money ("GBP 147,682.42") or a case or application number ("47676/99")
narrows down who a text is about, so the prose profile redacts them. In logs and
machine text the same shapes are everywhere and mostly harmless, so this tier is
off by default and on only in ``profile="prose"`` (or with
``use_prose_values=True``).

Every pattern is anchored on word boundaries only, so a match depends on at most
one character on each side of it; the declared bounds cover that.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType

_MAX_SPAN = 64

# ISO 4217 codes and currency words commonly written next to an amount
_CODES = (
    "EUR|USD|GBP|CHF|JPY|CNY|INR|AUD|CAD|NZD|SEK|NOK|DKK|ISK|PLN|CZK|HUF|RON|BGN|"
    "HRK|RUB|UAH|TRY|TRL|YTL|ZAR|BRL|MXN|ARS|ILS|AED|SAR|KRW|SGD|HKD|IEP|DEM|FRF|ITL|"
    "ESP|NLG|BEF|ATS|FIM|GRD|PTE|LUF"
)
_WORDS = (
    r"euros?|pounds?(?: sterling)?|dollars?|francs?|crowns?|kronor|kroner|krona|krone|"
    r"liras?|lire|zlotys?|zloty|roubles?|rubles?|rupees?|yen|marks?|pesetas?|escudos?|"
    r"drachmas?|forints?|lei|leva|hryvnias?|shekels?"
)
_NUM = r"\d{1,3}(?:[,. ]\d{3})*(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?"
_SCALE = r"(?:\s?(?:million|billion|thousand|m|bn|k)\b)?"

_PATTERNS: tuple[tuple[re.Pattern[str], EntityType], ...] = (
    # "GBP 147,682.42", "EUR 1,200", "£1,000", "€ 25", "$3.5 million"
    (
        re.compile(rf"(?:\b(?:{_CODES})\s?|[£€$¥])(?:{_NUM}){_SCALE}(?!\d)"),
        EntityType.MONEY,
    ),
    # "235,000 Swedish crowns", "150 New Turkish liras", "40,000 euros"
    (
        re.compile(rf"(?<![\d.,])(?:{_NUM}){_SCALE}\s(?:[A-Z][a-z]+\s){{0,2}}(?:{_WORDS})\b"),
        EntityType.MONEY,
    ),
    # a case, application or file number written as number/year: "47676/99"
    (re.compile(r"(?<![\w/.-])\d{2,6}/\d{2,4}(?![\w/]|\.\d)"), EntityType.ID_NUMBER),
    # a bare year 1800-2099 not attached to other digits or a slash-form number
    (re.compile(r"(?<![\w/.,-])(?:18|19|20)\d\d(?![\w/]|[.,]\d)"), EntityType.DATE),
)


class ProseValueDetector:
    """Years, money amounts and number/year references in prose (opt-in)."""

    name = "prose_values"
    requirements = StreamingRequirements(max_span=_MAX_SPAN, left_context=8, right_context=8)

    def __init__(self, years: bool = True) -> None:
        # bare years are dates: they follow the date setting (use_dates)
        self._patterns = [p for p in _PATTERNS if years or p[1] is not EntityType.DATE]

    def detect(self, text: str) -> list[Detection]:
        found: dict[tuple[int, int], Detection] = {}
        for pattern, etype in self._patterns:
            for m in pattern.finditer(text):
                start, end = m.span()
                value = m.group().rstrip(" ")
                end = start + len(value)
                if not value or end - start > _MAX_SPAN:
                    continue
                found.setdefault(
                    (start, end),
                    Detection(start, end, value, etype, 0.8, source=self.name),
                )
        return sorted(found.values(), key=lambda d: (d.start, d.end))
