"""Region-specific and checksum-validated identifiers (an opt-in detection tier).

IBAN, cryptocurrency addresses, UK National Insurance and NHS numbers, and India's
Aadhaar and PAN. These are **off by default** (``Redactor(use_regional=True)``,
``--regional``, or naming one of their types in ``types``) because turning them on
changes what an existing deployment redacts.

Precision comes from validating, not from clever regexes:

* **IBAN** — ISO 13616 mod-97 *and* the country's fixed length; an unknown country
  is rejected rather than guessed.
* **Bitcoin** — base58check (double-SHA-256) for legacy addresses, and the BIP-173/350
  polymod for bech32/bech32m. **Ethereum** addresses are matched by shape only: the
  EIP-55 mixed-case checksum needs Keccak-256, which the standard library does not
  have, so a 0x + 40-hex string is flagged whether or not its casing checksums.
* **NHS number** — mod-11. **Aadhaar** — Verhoeff. A bare run of 10 or 12 digits is
  ambiguous (an order id, a timestamp), so a plain run is accepted only when a cue
  word (``NHS``, ``Aadhaar``) sits just before it; the conventional spaced form
  (``943 476 5919``) is accepted on its own because its shape is deliberate.
* **UK NINO / India PAN** — no checksum exists, so only the published structural
  rules are applied (forbidden prefixes and letters; PAN holder-type letter).

Streaming safety: every rule is stateless and a pure function of one window. The
longest span is a spaced IBAN (42 characters) and the cue window looks 40 characters
left; both are declared in :class:`StreamingRequirements` so the engine's overlap
sizing and the equivalence theorems apply unchanged. Not mirrored in the native
core (the native parity gate covers the default tiers only), so
``backend="native"`` leaves this tier in Python.
"""

from __future__ import annotations

import hashlib
import re

from safestream_redactor.detectors.base import StreamingRequirements
from safestream_redactor.entities import Detection, EntityType

_CUE_WINDOW = 40
_MAX_SPAN = 64

# --- checksums ---------------------------------------------------------------

# ISO 13616 country -> total IBAN length (the common SEPA/European set).
_IBAN_LEN = {
    "AD": 24, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21,
    "HU": 28, "IE": 22, "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "TR": 26,
}  # fmt: skip


def iban_ok(compact: str) -> bool:
    """ISO 7064 mod-97-10 plus the country's fixed length (``compact`` has no spaces)."""
    if _IBAN_LEN.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def nhs_ok(digits: str) -> bool:
    """NHS number mod-11 (weights 10..2 over the first nine digits)."""
    if len(digits) != 10 or not digits.isdigit():
        return False
    check = 11 - sum(int(d) * w for d, w in zip(digits, range(10, 1, -1), strict=False)) % 11
    return check != 10 and (0 if check == 11 else check) == int(digits[9])


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)  # fmt: skip
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)  # fmt: skip


def verhoeff_ok(digits: str) -> bool:
    """Verhoeff dihedral-group checksum (the last digit is the check digit)."""
    if not digits.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def abn_ok(digits: str) -> bool:
    """Australian Business Number: subtract 1 from the first digit, weighted sum mod 89."""
    if len(digits) != 11 or not digits.isdigit():
        return False
    weights = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    values = [int(digits[0]) - 1, *map(int, digits[1:])]
    return sum(v * w for v, w in zip(values, weights, strict=True)) % 89 == 0


def acn_ok(digits: str) -> bool:
    """Australian Company Number: weights 8..1, check digit (10 - sum mod 10) mod 10."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits[:8], range(8, 0, -1), strict=True))
    return (10 - total % 10) % 10 == int(digits[8])


def tfn_ok(digits: str) -> bool:
    """Australian Tax File Number (8 or 9 digits), weighted sum mod 11."""
    weights = {9: (1, 4, 3, 7, 5, 8, 6, 9, 10), 8: (10, 7, 8, 4, 6, 3, 5, 1)}.get(len(digits))
    if weights is None or not digits.isdigit():
        return False
    return sum(int(d) * w for d, w in zip(digits, weights, strict=True)) % 11 == 0


def medicare_ok(digits: str) -> bool:
    """Australian Medicare card number (10 digits, or 11 with the issue number)."""
    if len(digits) not in (10, 11) or not digits.isdigit() or digits[0] not in "23456":
        return False
    total = sum(int(d) * w for d, w in zip(digits[:8], (1, 3, 7, 9, 1, 3, 7, 9), strict=True))
    return total % 10 == int(digits[8])


_NRIC_TABLE = {"S": "JZIHGFEDCBA", "T": "JZIHGFEDCBA", "F": "XWUTRQPNMLK", "G": "XWUTRQPNMLK"}


def nric_ok(value: str) -> bool:
    """Singapore NRIC (S/T) or FIN (F/G): weighted digits, +4 for the T/G series,
    mod 11, mapped to the series' check letter. (The M series' table is not
    implemented, so M numbers are not claimed.)"""
    if len(value) != 9 or value[0] not in _NRIC_TABLE or not value[1:8].isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(value[1:8], (2, 7, 6, 5, 4, 3, 2), strict=True))
    total += 4 if value[0] in "TG" else 0
    return _NRIC_TABLE[value[0]][total % 11] == value[8]


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_ok(address: str) -> bool:
    """Legacy Bitcoin address: 25 bytes, version 0 or 5, double-SHA-256 checksum."""
    n = 0
    for ch in address:
        i = _B58.find(ch)
        if i < 0:
            return False
        n = n * 58 + i
    try:
        raw = n.to_bytes(25, "big")
    except OverflowError:
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()
    return raw[0] in (0, 5) and digest[:4] == raw[21:]


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_ok(address: str) -> bool:
    """Segwit address checksum (bech32 for v0, bech32m for v1+), human part ``bc``."""
    if not address.startswith("bc1") or not 14 <= len(address) <= 74:
        return False
    try:
        data = [_BECH32.index(c) for c in address[3:]]
    except ValueError:
        return False
    values = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"] + data
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk in (1, 0x2BC830A3)


# --- patterns ----------------------------------------------------------------

_B = r"(?<![A-Za-z0-9])"  # left word edge (no \b: digits and letters both count)
_E = r"(?![A-Za-z0-9])"

_IBAN_START = re.compile(rf"{_B}[A-Z]{{2}}\d{{2}}(?= ?[A-Z0-9])")
_BTC_LEGACY = re.compile(rf"{_B}[13][1-9A-HJ-NP-Za-km-z]{{25,34}}{_E}")
_BTC_BECH32 = re.compile(rf"{_B}bc1[ac-hj-np-z02-9]{{11,71}}{_E}")
_ETH = re.compile(rf"{_B}0x[0-9a-fA-F]{{40}}{_E}")
# HMRC: first letter not D F I Q U V; second not D F I O Q U V; suffix A-D.
_NINO = re.compile(
    rf"{_B}[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z] ?\d{{2}} ?\d{{2}} ?\d{{2}} ?[A-D]{_E}"
)
_NINO_BAD_PREFIX = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})
_NHS = re.compile(rf"{_B}(\d{{3}}[ -]\d{{3}}[ -]\d{{4}}|\d{{10}}){_E}")
_AADHAAR = re.compile(rf"{_B}([2-9]\d{{3}} \d{{4}} \d{{4}}|[2-9]\d{{11}}){_E}")
_PAN = re.compile(rf"{_B}[A-Z]{{3}}[ABCFGHLJPT][A-Z]\d{{4}}[A-Z]{_E}")

# Checksummed national identifiers (default-on through ChecksumIdDetector). A
# plain digit run is ambiguous, so it needs a cue; the conventional spaced form is
# accepted alone only where it is distinctive (ABN 2-3-3-3, Medicare 4-5-1).
# ACN and TFN are 9 digits like many other numbers, so they always need a cue.
_ABN = re.compile(rf"{_B}(\d{{2}} \d{{3}} \d{{3}} \d{{3}}|\d{{11}}){_E}")
_NINE = re.compile(rf"{_B}(\d{{3}} \d{{3}} \d{{3}}|\d{{8,9}}){_E}")
_MEDICARE = re.compile(rf"{_B}([2-6]\d{{3}} \d{{5}} \d(?:[ -]?\d)?|[2-6]\d{{9,10}}){_E}")
_NRIC = re.compile(rf"{_B}[STFG]\d{{7}}[A-Z]{_E}")
# US ITIN: 9XX-XX-XXXX with an IRS-assigned group (50-65, 70-88, 90-92, 94-99).
_ITIN_SEP = re.compile(rf"{_B}9\d{{2}}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])-\d{{4}}{_E}")
_ITIN_BARE = re.compile(rf"{_B}9\d{{2}}(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\d{{4}}{_E}")
_ABN_CUE = re.compile(r"(?:\babn|business number)[^\n]{0,32}$", re.IGNORECASE)
_ACN_CUE = re.compile(r"(?:\bacn|company number)[^\n]{0,32}$", re.IGNORECASE)
_TFN_CUE = re.compile(r"(?:\btfn|tax file)[^\n]{0,32}$", re.IGNORECASE)
_MEDICARE_CUE = re.compile(r"medicare[^\n]{0,32}$", re.IGNORECASE)
_ITIN_CUE = re.compile(r"(?:\bitin|taxpayer id)[^\n]{0,32}$", re.IGNORECASE)

_NHS_CUE = re.compile(r"nhs[^\n]{0,32}$", re.IGNORECASE)
_AADHAAR_CUE = re.compile(r"(?:aadhaar|aadhar|uidai|uid)[^\n]{0,32}$", re.IGNORECASE)


def _iban_at(text: str, start: int) -> int | None:
    """End offset of the valid IBAN starting at ``start``, or ``None``.

    Only the two canonical forms are accepted: the electronic form (no spaces) and the
    print form (groups of four separated by one space, the last group 1-4 long). The
    country fixes the length, so exactly that many alphanumerics are taken instead of
    matching greedily: a greedy match followed by more capitals (``... 32 OR ...``)
    would overshoot, fail the checksum and hide the real IBAN. Free-form spacing
    (``GB82 W E S T ...``) is rejected: it is not an IBAN as anyone writes one.
    """
    need = _IBAN_LEN.get(text[start : start + 2])
    if need is None:
        return None
    grouped = text[start + 4 : start + 5] == " "
    i = start
    for taken in range(need):
        if grouped and taken and taken % 4 == 0:
            if text[i : i + 1] != " ":
                return None
            i += 1
        c = text[i : i + 1]
        if not (c.isascii() and c.isalnum() and (c.isdigit() or c.isupper())):
            return None
        i += 1
    if i < len(text) and text[i].isascii() and text[i].isalnum():
        return None
    return i if iban_ok(text[start:i].replace(" ", "")) else None


class RegionalDetector:
    """IBAN, crypto addresses, UK NINO/NHS, India Aadhaar/PAN, each validated."""

    name = "regional"
    requirements = StreamingRequirements(
        max_span=_MAX_SPAN, left_context=_CUE_WINDOW, right_context=1
    )

    @staticmethod
    def _cued(text: str, start: int, cue: re.Pattern[str]) -> bool:
        return cue.search(text[max(0, start - _CUE_WINDOW) : start]) is not None

    def _emit(
        self, text: str, start: int, end: int, kind: EntityType, conf: float, rule: str
    ) -> Detection:
        return Detection(start, end, text[start:end], kind, conf, self.name, {"rule": rule})

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        emit = self._emit
        for m in _IBAN_START.finditer(text):
            end = _iban_at(text, m.start())
            if end is not None:
                out.append(emit(text, m.start(), end, EntityType.IBAN, 0.9, "iban"))
        for m in _BTC_LEGACY.finditer(text):
            if base58check_ok(m.group()):
                out.append(emit(text, m.start(), m.end(), EntityType.CRYPTO_ADDRESS, 0.9, "btc"))
        for m in _BTC_BECH32.finditer(text):
            if bech32_ok(m.group()):
                out.append(emit(text, m.start(), m.end(), EntityType.CRYPTO_ADDRESS, 0.9, "bech32"))
        for m in _ETH.finditer(text):
            out.append(emit(text, m.start(), m.end(), EntityType.CRYPTO_ADDRESS, 0.85, "eth"))
        for m in _NINO.finditer(text):
            if m.group()[:2] not in _NINO_BAD_PREFIX:
                out.append(emit(text, m.start(), m.end(), EntityType.UK_NINO, 0.7, "nino"))
        for m in _NHS.finditer(text):
            spaced = not m.group(1).isdigit()
            if nhs_ok(re.sub(r"\D", "", m.group(1))) and (
                spaced or self._cued(text, m.start(), _NHS_CUE)
            ):
                out.append(emit(text, m.start(), m.end(), EntityType.NHS_NUMBER, 0.85, "nhs"))
        for m in _AADHAAR.finditer(text):
            spaced = " " in m.group(1)
            if verhoeff_ok(m.group(1).replace(" ", "")) and (
                spaced or self._cued(text, m.start(), _AADHAAR_CUE)
            ):
                out.append(emit(text, m.start(), m.end(), EntityType.IN_AADHAAR, 0.85, "aadhaar"))
        for m in _PAN.finditer(text):
            out.append(emit(text, m.start(), m.end(), EntityType.IN_PAN, 0.75, "pan"))
        return out


class ChecksumIdDetector(RegionalDetector):
    """Identifiers with a published checksum, on by default: IBAN, UK NHS, India
    Aadhaar, Australian ABN/ACN/TFN/Medicare, Singapore NRIC/FIN, and the US ITIN
    (IRS-assigned group ranges). Shape-only identifiers (NINO, PAN, crypto
    addresses) stay in the opt-in regional tier."""

    name = "checksum_id"

    def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        emit, cued = self._emit, self._cued
        for m in _IBAN_START.finditer(text):
            end = _iban_at(text, m.start())
            if end is not None:
                out.append(emit(text, m.start(), end, EntityType.IBAN, 0.9, "iban"))
        for m in _NHS.finditer(text):
            spaced = not m.group(1).isdigit()
            if nhs_ok(re.sub(r"\D", "", m.group(1))) and (
                spaced or cued(text, m.start(), _NHS_CUE)
            ):
                out.append(emit(text, m.start(), m.end(), EntityType.NHS_NUMBER, 0.85, "nhs"))
        for m in _AADHAAR.finditer(text):
            spaced = " " in m.group(1)
            if verhoeff_ok(m.group(1).replace(" ", "")) and (
                spaced or cued(text, m.start(), _AADHAAR_CUE)
            ):
                out.append(emit(text, m.start(), m.end(), EntityType.IN_AADHAAR, 0.85, "aadhaar"))
        for m in _ABN.finditer(text):
            spaced = " " in m.group(1)
            if abn_ok(m.group(1).replace(" ", "")) and (spaced or cued(text, m.start(), _ABN_CUE)):
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.85, "au_abn"))
        for m in _NINE.finditer(text):
            digits = m.group(1).replace(" ", "")
            if acn_ok(digits) and cued(text, m.start(), _ACN_CUE):
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.85, "au_acn"))
            elif tfn_ok(digits) and cued(text, m.start(), _TFN_CUE):
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.85, "au_tfn"))
        for m in _MEDICARE.finditer(text):
            spaced = " " in m.group(1)
            if medicare_ok(re.sub(r"\D", "", m.group(1))) and (
                spaced or cued(text, m.start(), _MEDICARE_CUE)
            ):
                rule = "au_medicare"
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.85, rule))
        for m in _NRIC.finditer(text):
            if nric_ok(m.group()):
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.85, "sg_nric"))
        for m in _ITIN_SEP.finditer(text):
            out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.8, "us_itin"))
        for m in _ITIN_BARE.finditer(text):
            if cued(text, m.start(), _ITIN_CUE):
                out.append(emit(text, m.start(), m.end(), EntityType.ID_NUMBER, 0.8, "us_itin"))
        return out
