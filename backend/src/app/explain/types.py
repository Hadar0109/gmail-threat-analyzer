"""Explanation layer types (internal).

Responsible for category/severity enums used by the registry and presenter.
Does not define API response models (see app.schemas).
"""

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
