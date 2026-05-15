"""Fixed sentence library for the main Gmail card (presentation only)."""

from __future__ import annotations

from app.explain.synthesis import ResolvedSignal
from app.explain.types import SynthesisTheme
from app.schemas import Verdict

# Main-card library — do not generate free-form copy.
SENTENCE_LIBRARY: dict[str, str] = {
    # Sender / identity
    "sender_not_verified": "The sender could not be fully verified.",
    "sender_company_mismatch": "The sender address looks different from the company mentioned in the message.",
    "sender_checks_incomplete": "Some technical checks could not verify the sender.",
    # Links / websites
    "unsafe_links": "Some links in this email may redirect to unsafe or misleading websites.",
    "external_sign_in": "This email asks you to sign in through an external link.",
    # Urgency / pressure
    "security_urgency_pressure": (
        "This message uses urgent security warnings and account threats to pressure you into taking immediate action."
    ),
    "immediate_action": "The message encourages immediate action without proper verification.",
    "urgency_pressure": "This email creates urgency to pressure quick action.",
    # Impersonation / phishing patterns
    "phishing_content": "This email includes content commonly seen in phishing or scam messages.",
    "impersonation_wording": "The message contains signs of impersonation or deceptive wording.",
    # Sensitive information
    "sensitive_verification": "This email requests account verification or sensitive information.",
    "login_personal_info": "The message asks for login details or personal information.",
    # Attachments
    "unsafe_attachments": "This email contains attachments that may be unsafe to open.",
    # General
    "unusual_formatting": "The message contains unusual wording or formatting patterns.",
    "parts_unusual": "Parts of this email appear unusual or inconsistent.",
}

_LIBRARY_PRIORITY: tuple[str, ...] = (
    "unsafe_attachments",
    "security_urgency_pressure",
    "sender_company_mismatch",
    "urgency_pressure",
    "external_sign_in",
    "unsafe_links",
    "sensitive_verification",
    "login_personal_info",
    "phishing_content",
    "impersonation_wording",
    "sender_not_verified",
    "sender_checks_incomplete",
    "immediate_action",
    "unusual_formatting",
    "parts_unusual",
)

_MAX_BRIEF_SENTENCES = 3

_PRESSURE_CORROBORATION_THEMES = frozenset(
    {
        SynthesisTheme.SENDER_TRUST,
        SynthesisTheme.SUSPICIOUS_SIGN_IN,
        SynthesisTheme.MALICIOUS_LINK,
    },
)

_STRONG_PRESSURE_MARKERS = (
    "security-alert",
    "suspended",
    "suspicious activity",
    "unauthorized access",
    "permanent account lock",
    "failure to act",
    "immediate password reset",
    "urgent fake security",
)


def _strong_phishing_pressure_keys(resolved: list[ResolvedSignal]) -> set[str]:
    """Promote social-engineering copy when pressure language is corroborated by sender/link risk."""
    themes = {row.theme for row in resolved}
    if not themes & _PRESSURE_CORROBORATION_THEMES:
        return set()

    pressure_rows = [
        row
        for row in resolved
        if row.theme == SynthesisTheme.PRESSURE_TACTICS
        or (
            row.theme == SynthesisTheme.PAYMENT_SENSITIVE
            and any(k in row.technical.lower() for k in ("password", "credential", "verify", "sign in"))
        )
    ]
    if not pressure_rows:
        return set()

    strong_markers = sum(
        1
        for row in pressure_rows
        if any(marker in row.technical.lower() for marker in _STRONG_PRESSURE_MARKERS)
    )
    if strong_markers >= 1 and len(pressure_rows) >= 2:
        return {"security_urgency_pressure"}
    if SynthesisTheme.PRESSURE_TACTICS in themes and strong_markers >= 2:
        return {"security_urgency_pressure"}
    return set()


def _library_key_for(row: ResolvedSignal) -> str | None:
    if row.theme in (SynthesisTheme.AUTH_CHECK, SynthesisTheme.TECHNICAL_DETAIL):
        return None

    t = row.technical.lower()

    if row.theme == SynthesisTheme.MALICIOUS_LINK:
        return "unsafe_links"
    if row.theme == SynthesisTheme.DANGEROUS_ATTACHMENT:
        return "unsafe_attachments"
    if row.theme == SynthesisTheme.SUSPICIOUS_SIGN_IN:
        if any(k in t for k in ("login", "verify", "credential", "sign in", "sign-in", "otp")):
            return "external_sign_in"
        return "unsafe_links"
    if row.theme == SynthesisTheme.SENDER_TRUST:
        if any(
            k in t
            for k in (
                "resembles",
                "display name",
                "brand",
                "official domain",
                "impersonation",
                "confusable",
            )
        ):
            return "sender_company_mismatch"
        if "reply-to" in t:
            return "sender_not_verified"
        return "sender_not_verified"
    if row.theme == SynthesisTheme.PAYMENT_SENSITIVE:
        if any(k in t for k in ("password", "credential", "login", "ssn", "2fa", "otp")):
            return "login_personal_info"
        return "sensitive_verification"
    if row.theme == SynthesisTheme.PRESSURE_TACTICS:
        if any(k in t for k in ("urgent", "immediate", "deadline", "act now")):
            return "urgency_pressure"
        return "immediate_action"
    if row.theme == SynthesisTheme.DELIVERY_SCAM:
        return "phishing_content"
    if row.theme == SynthesisTheme.GENERAL_CAUTION:
        return "parts_unusual"
    return None


def select_brief_sentences(
    resolved: list[ResolvedSignal],
    *,
    verdict: Verdict,
) -> list[str]:
    """Pick deduplicated library sentences for the main card (max 3)."""
    keys_present: set[str] = set()
    keys_present.update(_strong_phishing_pressure_keys(resolved))
    for row in resolved:
        key = _library_key_for(row)
        if key:
            keys_present.add(key)

    if verdict == Verdict.SAFE and not keys_present:
        return []

    ordered: list[str] = []
    for key in _LIBRARY_PRIORITY:
        if key in keys_present:
            ordered.append(SENTENCE_LIBRARY[key])

    return ordered[:_MAX_BRIEF_SENTENCES]
