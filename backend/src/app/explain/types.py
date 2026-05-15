"""Explanation layer types (internal)."""

from __future__ import annotations

from enum import StrEnum


class ExplanationCategory(StrEnum):
    SENDER_IDENTITY = "sender_identity"
    LINKS_WEBSITES = "links_websites"
    ATTACHMENTS = "attachments"
    URGENCY_PRESSURE = "urgency_pressure"
    SENSITIVE_REQUESTS = "sensitive_requests"
    REPUTATION = "reputation_warnings"
    SYSTEM = "system"


class ExplanationSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SynthesisTheme(StrEnum):
    """Merge bucket for related detector signals."""

    MALICIOUS_LINK = "malicious_link"
    DANGEROUS_ATTACHMENT = "dangerous_attachment"
    SENDER_TRUST = "sender_trust"
    SUSPICIOUS_SIGN_IN = "suspicious_sign_in"
    PAYMENT_SENSITIVE = "payment_sensitive"
    PRESSURE_TACTICS = "pressure_tactics"
    DELIVERY_SCAM = "delivery_scam"
    GENERAL_CAUTION = "general_caution"
    AUTH_CHECK = "auth_check"
    TECHNICAL_DETAIL = "technical_detail"


class DisplayTier(StrEnum):
    """Whether a signal may appear on the main card."""

    MAIN = "main"
    TECHNICAL = "technical"


CATEGORY_DISPLAY_ORDER: tuple[ExplanationCategory, ...] = (
    ExplanationCategory.SENDER_IDENTITY,
    ExplanationCategory.LINKS_WEBSITES,
    ExplanationCategory.ATTACHMENTS,
    ExplanationCategory.URGENCY_PRESSURE,
    ExplanationCategory.SENSITIVE_REQUESTS,
    ExplanationCategory.REPUTATION,
    ExplanationCategory.SYSTEM,
)

CATEGORY_LABELS: dict[ExplanationCategory, str] = {
    ExplanationCategory.SENDER_IDENTITY: "Sender identity",
    ExplanationCategory.LINKS_WEBSITES: "Links & websites",
    ExplanationCategory.ATTACHMENTS: "Attachments",
    ExplanationCategory.URGENCY_PRESSURE: "Urgency & pressure tactics",
    ExplanationCategory.SENSITIVE_REQUESTS: "Sensitive information requests",
    ExplanationCategory.REPUTATION: "Reputation warnings",
    ExplanationCategory.SYSTEM: "How this score was adjusted",
}

MAX_KEY_FINDINGS = 5
MIN_KEY_FINDINGS = 0
