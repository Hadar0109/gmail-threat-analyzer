"""Resolve internal detector reason strings to user-facing explanations."""

from __future__ import annotations

from app.explain.registry import EXACT, _PATTERN_RULES, ExplanationSpec
from app.explain.types import ExplanationCategory, ExplanationSeverity


def resolve_reason(technical: str) -> ExplanationSpec:
    """Map one internal reason string to a user-facing explanation (deterministic)."""
    text = technical.strip()
    if not text:
        return _fallback(text)

    exact = EXACT.get(text)
    if exact is not None:
        return exact

    for pattern, spec in _PATTERN_RULES:
        if pattern.search(text):
            return spec

    return _fallback(text)


def _fallback(technical: str) -> ExplanationSpec:
    """Conservative default when no registry entry matches."""
    lowered = technical.lower()
    category = ExplanationCategory.SYSTEM
    severity = ExplanationSeverity.MEDIUM

    if any(k in lowered for k in ("url", "link", "host", "http")):
        category = ExplanationCategory.LINKS_WEBSITES
        severity = ExplanationSeverity.MEDIUM
        message = "This email contains a link that may lead to an unsafe website."
        guidance = "Avoid clicking links until you verify the sender."
    elif any(k in lowered for k in ("attachment", "filename", "macro", "archive")):
        category = ExplanationCategory.ATTACHMENTS
        severity = ExplanationSeverity.MEDIUM
        message = "An attachment in this message may not be safe to open."
        guidance = "Open attachments only after confirming you trust the sender."
    elif any(k in lowered for k in ("spf", "dkim", "dmarc", "authentication", "reply-to", "domain", "sender", "display name", "brand")):
        category = ExplanationCategory.SENDER_IDENTITY
        severity = ExplanationSeverity.MEDIUM
        message = "Something about the sender or how this message was sent looks unusual."
        guidance = "Confirm the sender before replying or clicking links."
    elif any(k in lowered for k in ("password", "credential", "verify", "ssn", "payroll", "wire", "payment", "invoice")):
        category = ExplanationCategory.SENSITIVE_REQUESTS
        severity = ExplanationSeverity.HIGH
        message = "The message asks for sensitive information or payment action."
        guidance = "Be careful sharing passwords or payment details in response to this email."
    elif any(k in lowered for k in ("urgent", "immediate", "deadline", "security alert", "suspended")):
        category = ExplanationCategory.URGENCY_PRESSURE
        severity = ExplanationSeverity.MEDIUM
        message = "The message uses pressure or alarming language."
        guidance = "Pause and verify before acting on urgent requests."
    elif any(k in lowered for k in ("safe browsing", "virustotal", "reputation", "threat")):
        category = ExplanationCategory.REPUTATION
        severity = ExplanationSeverity.HIGH
        message = "External link checks reported warning signs for this message."
        guidance = "Avoid clicking links until you verify the sender."
    else:
        message = "This message triggered a caution flag during automated review."
        guidance = "Review the sender and links carefully before interacting."

    return ExplanationSpec(category, severity, message, guidance)
