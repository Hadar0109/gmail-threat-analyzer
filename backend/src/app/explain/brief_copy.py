"""Fixed sentence library for the main Gmail card (presentation only)."""

from __future__ import annotations

from app.explain.synthesis import ResolvedSignal
from app.explain.types import SynthesisTheme
from app.schemas import Verdict

# Approved user-facing sentences — do not add or generate new copy here.
SENTENCE_LIBRARY: dict[str, str] = {
    "links_attachments": "This email contains suspicious links or attachments.",
    "sender_not_verified": "The sender could not be fully verified.",
    "sensitive_request": "This email requests sensitive information or account verification.",
    "unsafe_links": "Some links in this email may redirect to unsafe or misleading websites.",
    "unusual_formatting": "The message contains unusual formatting or wording patterns.",
    "scam_impersonation": "This email includes content often used in scam or impersonation campaigns.",
    "immediate_action": "The message encourages immediate action without proper verification.",
}

CHECKED_NOTICE = "This email was checked."

# Priority when multiple risk types apply (higher first).
_LIBRARY_PRIORITY: tuple[str, ...] = (
    "links_attachments",
    "unsafe_links",
    "sensitive_request",
    "scam_impersonation",
    "sender_not_verified",
    "immediate_action",
    "unusual_formatting",
)

_THEME_TO_LIBRARY_KEY: dict[SynthesisTheme, str] = {
    SynthesisTheme.MALICIOUS_LINK: "unsafe_links",
    SynthesisTheme.DANGEROUS_ATTACHMENT: "links_attachments",
    SynthesisTheme.SENDER_TRUST: "sender_not_verified",
    SynthesisTheme.SUSPICIOUS_SIGN_IN: "unsafe_links",
    SynthesisTheme.PAYMENT_SENSITIVE: "sensitive_request",
    SynthesisTheme.PRESSURE_TACTICS: "immediate_action",
    SynthesisTheme.DELIVERY_SCAM: "scam_impersonation",
    SynthesisTheme.GENERAL_CAUTION: "unusual_formatting",
}

_MAX_BRIEF_SENTENCES = 3


def _library_key_for(row: ResolvedSignal) -> str | None:
    if row.theme in (SynthesisTheme.AUTH_CHECK, SynthesisTheme.TECHNICAL_DETAIL):
        return None
    if row.theme == SynthesisTheme.SENDER_TRUST:
        t = row.technical.lower()
        if any(
            k in t
            for k in (
                "resembles",
                "impersonation",
                "brand",
                "display name references",
                "confusable",
                "official domain",
            )
        ):
            return "scam_impersonation"
        return "sender_not_verified"
    return _THEME_TO_LIBRARY_KEY.get(row.theme)


def select_brief_sentences(
    resolved: list[ResolvedSignal],
    *,
    verdict: Verdict,
) -> list[str]:
    """Pick deduplicated library sentences for the main card (max 3)."""
    if verdict == Verdict.SAFE:
        keys_seen: set[str] = set()
        for row in resolved:
            key = _library_key_for(row)
            if key:
                keys_seen.add(key)
        if not keys_seen:
            return []

    keys_present: set[str] = set()
    for row in resolved:
        key = _library_key_for(row)
        if key:
            keys_present.add(key)

    ordered: list[str] = []
    for key in _LIBRARY_PRIORITY:
        if key in keys_present:
            ordered.append(SENTENCE_LIBRARY[key])

    return ordered[:_MAX_BRIEF_SENTENCES]
