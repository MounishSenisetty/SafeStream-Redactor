"""Structured fields: the field name says what the value is.

JSON and dict entries (``"LastName": "Arap"``), XML elements (``<Phone>…</Phone>``),
``Label: value`` lines (YAML, forms, markdown lists) and ``key=value`` pairs carry a
name that types their value better than any pattern on the value alone. This tier
reads that name and redacts **only the value**.

The field-name vocabulary is taken from public schemas, not from any evaluation
corpus: vCard (``fn``, ``given-name``, ``family-name``, ``tel``, ``bday``, ``adr``),
schema.org Person and PostalAddress (``givenName``, ``familyName``,
``streetAddress``, ``postalCode``, ``addressLocality``, ``telephone``,
``birthDate``), FHIR Patient (``name.given``, ``name.family``, ``telecom``,
``birthDate``, ``gender``) and common form labels (date of birth, passport number,
driver's licence). A name is normalised (lower case, separators removed, a trailing
index dropped: ``GivenName2`` -> ``givenname``) before lookup.

Precision guards, because logs are full of ``"name": "api-gateway"`` and
``"state": "RUNNING"``:

* each type has a value validator (a person value is 1-4 capitalised words; a
  phone has at least seven digits; an identifier has a digit; place fields
  reject status words);
* placeholders and references are never values: ``null``, ``None``, ``""``,
  ``${VAR}``, ``$VAR``, ``%VAR%``, ``{{ var }}``, ``os.environ[…]``,
  ``process.env.X``, ``getenv(…)``, ``<redacted>``, ``****``;
* generic names that are mostly not personal data in machine text (``id``,
  ``title``, ``region``) are not in the vocabulary, and ``name`` counts only with
  a person-shaped value. Gender/sex and honorific fields are prose-profile only.

All patterns are lookaround-free and bounded: a key is at most 48 characters, a
value at most ``_MAX_VALUE``, so the tier declares a fixed streaming requirement.
"""

from __future__ import annotations

import re

from safestream_redactor.detectors.base import StreamingRequirements, is_placeholder
from safestream_redactor.detectors.labeled_id import dob_value_pattern
from safestream_redactor.entities import Detection, EntityType

_DOB_VALUE = dob_value_pattern()
_DOB_FULL = re.compile(rf"(?:{_DOB_VALUE})\Z", re.IGNORECASE)

_MAX_VALUE = 128
_MAX_KEY = 48

# --- field-name vocabulary (normalised names) ---------------------------------

_PERSON = {
    "name", "fullname", "fn", "firstname", "givenname", "forename", "lastname",
    "familyname", "surname", "middlename", "additionalname", "maidenname",
    "patientname", "customername", "clientname", "employeename", "contactname",
    "cardholdername", "cardholder", "accountholder", "accountholdername", "nameoncard",
    "spousename", "nextofkin", "emergencycontactname",
}  # fmt: skip
_ADDRESS = {
    "address", "streetaddress", "street", "addressline", "addr", "adr", "homeaddress",
    "mailingaddress", "billingaddress", "shippingaddress", "postaladdress",
    "residentialaddress", "residence", "building", "buildingnumber", "buildingno",
    "housenumber", "houseno", "apartment", "apt", "suite", "flat", "secondaryaddress",
    "postcode", "postalcode", "zip", "zipcode", "city", "town", "village",
    "addresslocality", "addressregion", "state", "province", "county", "country",
    "addresscountry", "countryname", "birthplace", "placeofbirth",
}  # fmt: skip
_PHONE = {
    "phone", "phonenumber", "phoneno", "telephone", "telephonenumber", "tel", "mobile",
    "mobilenumber", "mobilephone", "cell", "cellphone", "cellnumber", "fax", "faxnumber",
    "homephone", "workphone", "contactnumber", "telecom",
}  # fmt: skip
_DOB = {"dob", "dateofbirth", "birthdate", "birthday", "bday"}
_ID = {
    "idnumber", "idno", "idcard", "idcardnumber", "identitycard", "identitynumber",
    "nationalid", "nationalidnumber", "nationalidentifier", "passport", "passportnumber",
    "passportno", "driverslicense", "driverlicense", "driverslicence", "driverlicence",
    "drivinglicense", "drivinglicence", "licensenumber", "licencenumber", "dlnumber",
    "socialsecuritynumber", "ssn", "socialnumber", "socialinsurancenumber", "sin",
    "taxid", "taxnumber", "tin", "nin", "ninumber", "nationalinsurancenumber",
    "nhsnumber", "medicalrecordnumber", "mrn", "patientid", "memberid", "employeeid",
    "studentid", "accountnumber", "bankaccount", "bankaccountnumber", "iban",
    "insurancenumber", "policynumber", "voterid", "aadhaar", "pan",
}  # fmt: skip
_USERNAME = {"username", "user", "login", "handle", "loginname", "userlogin"}
_PROSE_ONLY = {"sex": EntityType.SEX, "gender": EntityType.SEX}
_PROSE_ONLY |= dict.fromkeys(("honorific", "salutation", "jobtitle"), EntityType.TITLE)

_TYPE_OF: dict[str, EntityType] = {}
_TYPE_OF |= dict.fromkeys(_PERSON, EntityType.PERSON)
_TYPE_OF |= dict.fromkeys(_ADDRESS, EntityType.ADDRESS)
_TYPE_OF |= dict.fromkeys(_PHONE, EntityType.PHONE)
_TYPE_OF |= dict.fromkeys(_DOB, EntityType.DOB)
_TYPE_OF |= dict.fromkeys(_ID, EntityType.ID_NUMBER)
_TYPE_OF |= dict.fromkeys(_USERNAME, EntityType.USERNAME)

_NORMALISE = re.compile(r"[^a-z]+")
_TRAILING_INDEX = re.compile(r"\d+$")


# Other common field labels: not redacted by this tier, but they end a line value.
_OTHER_LABELS = frozenset(
    {"email", "emailaddress", "mail", "website", "url", "company", "organization",
     "organisation", "occupation", "age", "notes", "comment", "date", "time", "status"}
)  # fmt: skip


def _norm(key: str) -> str:
    return _NORMALISE.sub("", _TRAILING_INDEX.sub("", key.strip().lower()))


# A field whose name ends like this holds a secret (FromEmailPassword, vm_password,
# DB_PASS, client_secret, X-Auth-Token, AccountKey, ConnectionString_B2B). Suffixes,
# not substrings: password_policy, token_type and passwordExpiry are not secrets.
_SECRET_SUFFIXES = (
    "password", "passwd", "passphrase", "pwd", "pass", "pswd", "secret", "token",
    "apikey", "accesskey", "secretkey", "privatekey", "signingkey", "encryptionkey",
    "masterkey", "authkey", "accountkey", "sharedaccesskey", "credential",
    "credentials", "connectionstring", "connstring", "dsn",
)  # fmt: skip
_SECRET_EXACT = frozenset({"pw", "pin", "otp", "cvv", "cvc"})
# Field names that mean something else in a URL query (OAuth "state" is a CSRF
# nonce, not a place), so they are not personal data there.
_QUERY_NOT_PII = frozenset({"state"})
# Extra names that are sensitive as URL query parameters (after ? or &) but too
# generic as field names elsewhere: ?key=, ?sig=, ?session=, ?code=, ?email=
_QUERY_TYPES: dict[str, EntityType] = {
    **dict.fromkeys(("email", "mail", "emailaddress", "e"), EntityType.EMAIL),
    **dict.fromkeys(
        (
            "key",
            "sig",
            "signature",
            "session",
            "sessionid",
            "sid",
            "auth",
            "code",
            "otp",
            "hash",
            "jwt",
            "bearer",
        ),
        EntityType.SECRET,
    ),
}


def field_type(key: str, prose: bool = False) -> EntityType | None:
    """The entity type a field name announces, or ``None``."""
    norm = _norm(key)
    found = _TYPE_OF.get(norm)
    if found is None and norm.endswith("username"):  # smtp_username, REACT_APP_AUTH_USERNAME
        found = EntityType.USERNAME
    secretish = norm in _SECRET_EXACT or norm.endswith(_SECRET_SUFFIXES)
    if found is None and secretish and not norm.endswith(("bypass", "compass")):
        found = EntityType.SECRET
    if found is None and prose:
        found = _PROSE_ONLY.get(norm)
    return found


# --- value validators ------------------------------------------------------------

_PERSON_VALUE = re.compile(r"\A[A-Z][A-Za-z'.-]*(?:[ ,][ ]?[A-Z][A-Za-z'.-]*){0,3}\Z")
_PHONE_VALUE = re.compile(r"\A\+?[\d\s().\-/x]{7,40}\Z")
_HAS_DIGIT = re.compile(r"\d")
_USERNAME_VALUE = re.compile(r"\A[^\s\"'<>]{2,64}\Z")
_PLACE_VALUE = re.compile(r"\A[^\s\"<>{}][^\"<>{}]{0,127}\Z")
_STATUS_WORDS = frozenset(
    [
        "running",
        "stopped",
        "active",
        "inactive",
        "pending",
        "failed",
        "failure",
        "error",
        "success",
        "succeeded",
        "ok",
        "okay",
        "open",
        "closed",
        "enabled",
        "disabled",
        "true",
        "false",
        "yes",
        "no",
        "ready",
        "done",
        "new",
        "idle",
        "up",
        "down",
        "unknown",
        "started",
        "starting",
        "stopping",
        "complete",
        "completed",
        "healthy",
        "unhealthy",
        "online",
        "offline",
        "valid",
        "invalid",
        "default",
        "any",
        "all",
    ]
)


_SWITCH_WORDS = frozenset(
    {"true", "false", "yes", "no", "on", "off", "enabled", "disabled", "required", "optional"}
)


def _valid(etype: EntityType, value: str) -> bool:
    if is_placeholder(value):
        return False
    if etype is EntityType.PERSON:
        return bool(_PERSON_VALUE.match(value)) and value.lower() not in _STATUS_WORDS
    if etype is EntityType.PHONE:
        return bool(_PHONE_VALUE.match(value)) and sum(c.isdigit() for c in value) >= 7
    if etype is EntityType.DOB:
        return bool(_DOB_FULL.match(value))
    if etype is EntityType.ID_NUMBER:
        return bool(_HAS_DIGIT.search(value)) and len(value) <= 64
    if etype is EntityType.USERNAME:
        return bool(_USERNAME_VALUE.match(value)) and value.lower() not in _STATUS_WORDS
    if etype is EntityType.EMAIL:
        return "@" in value or "%40" in value.lower()
    if etype is EntityType.SECRET:
        # any non-placeholder value of 3+ characters, letters-only included
        # ("open sesame"); a bare boolean or switch word is configuration
        return 3 <= len(value) <= _MAX_VALUE and value.lower() not in _SWITCH_WORDS
    # ADDRESS, SEX, TITLE: free text, but never a status word or a bare boolean
    return bool(_PLACE_VALUE.match(value)) and value.lower() not in _STATUS_WORDS


# A line value has no closing delimiter, so it is cut to the part its type can be:
# another "Label:" on the same line ends it, and each type keeps its longest valid
# prefix ("Student ID: 202184673 enrolled" -> "202184673").
_COLON = re.compile(r"[ \t]*[:=][ \t]")
_WORD_BEFORE = re.compile(r"[A-Za-z][A-Za-z0-9_'.()/-]*\Z")


def _next_label(value: str) -> int | None:
    """Where another known field label starts inside a line value, if anywhere.

    Only a *known* field name counts ("Name: John Smith Phone: …" is cut before
    "Phone", never before "Smith Phone"): the one to four words before a colon are
    tried longest first against the vocabulary.
    """
    for colon in _COLON.finditer(value):
        words: list[tuple[int, str]] = []
        head = value[: colon.start()]
        while len(words) < 4:
            m = _WORD_BEFORE.search(head.rstrip())
            if m is None:
                break
            words.append((m.start(), m.group()))
            head = head[: m.start()]
        for n in range(len(words), 0, -1):
            start = words[n - 1][0]
            label = " ".join(w for _, w in reversed(words[:n]))
            if start > 0 and (field_type(label, prose=True) or _norm(label) in _OTHER_LABELS):
                return start
    return None


_TOKEN = re.compile(r"\S+")
_ID_TOKEN = re.compile(r"[A-Za-z0-9./-]*\d[A-Za-z0-9./-]*|[A-Z0-9./-]+")


def _id_prefix(value: str) -> str:
    """Leading whole tokens that look like identifier parts (a digit, or all caps)."""
    end = 0
    for i, tok in enumerate(_TOKEN.finditer(value)):
        if i == 6 or not _ID_TOKEN.fullmatch(tok.group()):
            break
        end = tok.end()
    return value[:end]


_LINE_PREFIX: dict[EntityType, re.Pattern[str]] = {
    EntityType.PERSON: re.compile(r"[A-Z][A-Za-z'.-]*(?: [A-Z][A-Za-z'.-]*){0,3}"),
    EntityType.PHONE: re.compile(r"\+?[\d(][\d\s().\-/x]{6,39}\d"),
    # the same date shapes the label-anchored DOB rule accepts
    EntityType.DOB: re.compile(_DOB_VALUE, re.IGNORECASE),
    EntityType.USERNAME: re.compile(r"[^\s\"'<>,;]+"),
}


def _line_value(etype: EntityType, value: str) -> str:
    cut = _next_label(value)
    if cut is not None:
        value = value[:cut]
    value = value.rstrip(_TRIM)
    if is_placeholder(value):  # judge the whole value before cutting it to a prefix
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value  # a quoted value is delimited: the caller unquotes and checks it
    if etype is EntityType.ID_NUMBER:
        return _id_prefix(value)
    if etype is EntityType.SECRET:
        # an unquoted secret is one token: "password = abuser1234  # comment"
        return value.split()[0] if value.split() else ""
    if etype is EntityType.USERNAME and any(c.isspace() for c in value):
        # a username field holds one token; "User1: Thank you, User2" is a
        # transcript speaker label followed by a sentence, not a username
        return ""
    prefix = _LINE_PREFIX.get(etype)
    if prefix is None:
        return value
    m = prefix.match(value)
    return m.group() if m else ""


# --- forms ---------------------------------------------------------------------------

_KEY = rf"[A-Za-z][A-Za-z0-9 _'.()/-]{{0,{_MAX_KEY - 1}}}"
_V = _MAX_VALUE

# "key": "value" / 'key': 'value' / "key": 12345 (JSON, Python dicts, JS objects)
_JSON = re.compile(
    rf"[\"']({_KEY})[\"'][ \t]*:[ \t]*"
    rf"(?:\"([^\"\\\n]{{1,{_V}}})\"|'([^'\\\n]{{1,{_V}}})'|(\+?[0-9][0-9 ().\-]{{0,38}}[0-9]))"
)
# <Key>value</Key> (the closing name is checked in code: no backreference)
_XML = re.compile(rf"<({_KEY})>([^<>\n]{{1,{_V}}})</({_KEY})>")
# Label: value / key = value at the start of a line, after optional indentation,
# a list bullet and markdown emphasis; the value runs to the end of the line
_LINE = re.compile(
    rf"(?m)^[ \t]*(?:[-*>][ \t]+|\d{{1,3}}[.)][ \t]+)?(?:\*\*|__)?({_KEY}?)(?:\*\*|__)?"
    rf"[ \t]*[:=][ \t]*(?:\*\*|__)?[ \t]*([^\n]{{1,{_V}}})"
)
# key=value pairs inside a line (logfmt, .env, query strings)
_PAIR = re.compile(
    rf"(?:^|[\s?&;,(])([A-Za-z][A-Za-z0-9_.-]{{0,{_MAX_KEY - 1}}})="
    rf"(?:\"([^\"\n]{{1,{_V}}})\"|'([^'\n]{{1,{_V}}})'|([^\s&;,\"'<>()]{{1,{_V}}}))"
)
_TRIM = " \t,;"

# Secret-only forms (a secret field's value may sit anywhere on a line):
# a quoted value assigned to an identifier: $mail->Password = 'x', :password => 'x',
# my_password := "x", vm_password': "x"; the key is the identifier before the operator
_ASSIGN = re.compile(
    rf"([A-Za-z_][A-Za-z0-9_]{{0,{_MAX_KEY - 1}}})[\"']?[ \t]*(?:=>|:=|=|:)[ \t]*"
    rf"(?:\"([^\"\n]{{1,{_V}}})\"|'([^'\n]{{1,{_V}}})')"
)
# .NET appSettings: <add key="SmtpPassword" value="x" />
_KEY_VALUE_ATTRS = re.compile(rf"\bkey=\"({_KEY})\"[ \t]+value=\"([^\"\n]{{1,{_V}}})\"")
# prose: "The default password is 'blooberry'" (quoted values only)
_PROSE_SECRET = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|passcode|pin)[ \t]+(?:is|was)[ \t]*:?[ \t]*"
    r"(?:\"([^\"\n]{3,64})\"|'([^'\n]{3,64})')"
)
# the user part of a URI's userinfo (scheme://user:password@host): a username
# field; the password is the deterministic tier's url_credentials
_USERINFO = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://([^\s:/@\"'<>]{1,64}):[^\s/@\"'<>]{1,128}@")


class StructuredFieldDetector:
    """Redacts the value of a field whose name says it is personal data."""

    name = "structured_field"
    # The key and its separators sit left of the value; deciding where a line value
    # ends reads up to the value cap past its start (docs/FORMAL_MODEL.md 3.2).
    requirements = StreamingRequirements(
        max_span=_MAX_VALUE, left_context=_MAX_KEY + 16, right_context=_MAX_VALUE
    )

    def __init__(self, prose: bool = False, confidence: float = 0.8) -> None:
        self.prose = prose
        self.confidence = confidence

    def detect(self, text: str) -> list[Detection]:
        found: dict[tuple[int, int], Detection] = {}

        def emit(key: str, start: int, end: int, line: bool = False, query: bool = False) -> None:
            etype = field_type(key, self.prose)
            if query and _norm(key) in _QUERY_NOT_PII:
                etype = None
            elif etype is None and query:  # a URL query parameter: its own vocabulary
                etype = _QUERY_TYPES.get(_norm(key))
            if etype is None:
                return
            raw = text[start:end]
            value = _line_value(etype, raw) if line else raw.rstrip(_TRIM)
            # a line value may be quoted: emit only what is inside the quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                start, value = start + 1, value[1:-1]
            if not value or not _valid(etype, value):
                return
            end = start + len(value)
            if (start, end) not in found:
                found[(start, end)] = Detection(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=etype,
                    confidence=self.confidence,
                    source=self.name,
                    meta={"field": key.strip()[:32]},
                )

        def first_group(m: re.Match[str], groups: range) -> tuple[int, int] | None:
            for g in groups:
                if m.start(g) >= 0:
                    return m.start(g), m.end(g)
            return None

        if ":" in text:
            for m in _JSON.finditer(text):
                span = first_group(m, range(2, 5))
                if span:
                    emit(m.group(1), *span)
        if "</" in text:
            for m in _XML.finditer(text):
                if m.group(1).lower() == m.group(3).lower():
                    emit(m.group(1), m.start(2), m.end(2))
        if ":" in text or "=" in text:
            for m in _LINE.finditer(text):
                emit(m.group(1), m.start(2), m.end(2), line=True)
        if "=" in text:
            for m in _PAIR.finditer(text):
                span = first_group(m, range(2, 5))
                if span:
                    emit(m.group(1), *span, query=m.group(0)[0] in "?&")
            for m in _KEY_VALUE_ATTRS.finditer(text):
                emit(m.group(1), m.start(2), m.end(2))
        if "=" in text or ":" in text:
            for m in _ASSIGN.finditer(text):
                span = first_group(m, range(2, 4))
                if span and field_type(m.group(1)) is EntityType.SECRET:
                    emit(m.group(1), *span)
        for m in _PROSE_SECRET.finditer(text):
            span = first_group(m, range(1, 3))
            if span:
                emit("password", *span)
        if "://" in text:
            for m in _USERINFO.finditer(text):
                emit("username", m.start(1), m.end(1))
        return sorted(found.values(), key=lambda d: (d.start, d.end))
