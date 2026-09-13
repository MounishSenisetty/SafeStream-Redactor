"""Severity classification for detected entity types.

A shared, content-free severity scale used by the MCP server and the SARIF
exporter so a leaked AWS secret and a phone number are not treated as equally
urgent. Severity is a static property of the entity *type*, never of the matched
text, so nothing here touches the secret itself.
"""

from __future__ import annotations

from safestream_redactor.entities import EntityType

# Four levels, ordered. "critical" is a live credential that grants access;
# "high" is a credential or key material; "medium" is regulated PII; "low" is
# weakly identifying or ambiguous.
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY: dict[EntityType, str] = {
    # Credentials / key material — a leak is directly exploitable.
    EntityType.AWS_KEY: CRITICAL,
    EntityType.AWS_SECRET: CRITICAL,
    EntityType.PRIVATE_KEY: CRITICAL,
    EntityType.GITHUB_TOKEN: CRITICAL,
    EntityType.SLACK_TOKEN: CRITICAL,
    EntityType.STRIPE_KEY: CRITICAL,
    EntityType.OPENAI_KEY: CRITICAL,
    EntityType.ANTHROPIC_KEY: CRITICAL,
    EntityType.SENDGRID_KEY: CRITICAL,
    EntityType.TWILIO_KEY: CRITICAL,
    EntityType.NPM_TOKEN: CRITICAL,
    EntityType.GOOGLE_API_KEY: CRITICAL,
    EntityType.SLACK_WEBHOOK: HIGH,
    EntityType.JWT: HIGH,
    EntityType.API_KEY: HIGH,
    EntityType.URL_CREDENTIALS: HIGH,
    EntityType.SECRET: HIGH,
    # Regulated / directly identifying PII.
    EntityType.SSN: HIGH,
    EntityType.CREDIT_CARD: HIGH,
    EntityType.ID_NUMBER: HIGH,
    EntityType.DOB: MEDIUM,
    EntityType.EMAIL: MEDIUM,
    EntityType.PHONE: MEDIUM,
    EntityType.PERSON: MEDIUM,
    # Weakly identifying or ambiguous.
    EntityType.IPV4: LOW,
    EntityType.IPV6: LOW,
    EntityType.ORG: LOW,
    EntityType.LOC: LOW,
    EntityType.CUSTOM: MEDIUM,
}


def severity_for(entity_type: EntityType) -> str:
    """Severity level (``critical``/``high``/``medium``/``low``) for a type."""
    return _SEVERITY.get(entity_type, MEDIUM)
