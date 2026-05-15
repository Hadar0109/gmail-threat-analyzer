"""Combo rule definitions.

Responsible for archetype combo patterns and rule metadata.
Does not execute vendor reputation checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.scoring.combos.context import ScoringContext, _MEDIUM_SEVERITY_TAGS
from app.scoring.parsing.domains import domain_from_address, domains_equal
from app.scoring.signals.urls import has_off_domain_untrusted_url
RULES_VERSION = "1.0.0"

_ARCHIVE_TAGS = frozenset(
    {"archive_attachment", "password_protected_archive", "macro_attachment"},
)
_MALWARE_ATTACHMENT_TAGS = frozenset(
    {"executable_attachment", "double_extension"},
)
_FINANCIAL_INVOICE_TAGS = frozenset({"financial_request", "invoice_language"})
_IDENTITY_MISMATCH_TAGS = frozenset(
    {
        "display_name_brand_mismatch",
        "brand_mention_foreign_sender",
        "lookalike_domain",
        "subdomain_deception",
    },
)


@dataclass(frozen=True, slots=True)
class ComboRule:
    id: str
    priority: int
    boost: float
    reason: str
    when: Callable[[ScoringContext], bool]


def _has(ctx: ScoringContext, *tags: str) -> bool:
    return any(t in ctx.tags for t in tags)


def _cred_external(ctx: ScoringContext) -> bool:
    if not _has(ctx, "credential_request"):
        return False
    if _has(ctx, "external_link"):
        return True
    return has_off_domain_untrusted_url(ctx.req, legitimacy=ctx.legitimacy)


def _off_domain_link_signal(ctx: ScoringContext) -> bool:
    return _has(ctx, "external_link") or has_off_domain_untrusted_url(
        ctx.req,
        legitimacy=ctx.legitimacy,
    )


def _account_takeover_external(ctx: ScoringContext) -> bool:
    content = _has(ctx, "credential_request") or _has(ctx, "fake_security_alert")
    if not content or not _off_domain_link_signal(ctx):
        return False
    return _has(ctx, "login_like_path") or _has(ctx, "suspicious_tld")


def _generic_security_phish(ctx: ScoringContext) -> bool:
    if not (_has(ctx, "generic_greeting") or _has(ctx, "generic_security_sender")):
        return False
    content = _has(ctx, "credential_request") or _has(ctx, "fake_security_alert")
    return content and _off_domain_link_signal(ctx) and _has(ctx, "login_like_path")


def _bank_urgency(ctx: ScoringContext) -> bool:
    return _has(ctx, "financial_request") and (
        _has(ctx, "urgency_language") or _has(ctx, "fake_security_alert")
    )


def _invoice_attachment(ctx: ScoringContext) -> bool:
    return _has(ctx, "invoice_language") and bool(_ARCHIVE_TAGS & ctx.tags)


def _gift_card_urgency_external(ctx: ScoringContext) -> bool:
    return (
        _has(ctx, "crypto_refund_language")
        and _has(ctx, "urgency_language")
        and (_off_domain_link_signal(ctx) or _has(ctx, "suspicious_tld"))
    )


def _invoice_malware_attachment(ctx: ScoringContext) -> bool:
    return bool(_FINANCIAL_INVOICE_TAGS & ctx.tags) and bool(
        _MALWARE_ATTACHMENT_TAGS & ctx.tags
    )


def _otp_login(ctx: ScoringContext) -> bool:
    return _has(ctx, "otp_language") and _has(ctx, "login_like_path")


def _pay_sender_mismatch(ctx: ScoringContext) -> bool:
    if not _has(ctx, "financial_request"):
        return False
    if _has(ctx, "suspicious_sender"):
        return True
    return bool(_IDENTITY_MISMATCH_TAGS & ctx.tags)


def _fake_sec_alert(ctx: ScoringContext) -> bool:
    return (
        _has(ctx, "fake_security_alert")
        and _off_domain_link_signal(ctx)
        and (
            _has(ctx, "brand_mention_foreign_sender")
            or _has(ctx, "display_name_brand_mismatch")
            or _has(ctx, "brand_url_mismatch")
        )
    )


def _weak_signal_stack(ctx: ScoringContext) -> bool:
    if ctx.auth == "all_pass":
        return False
    medium_tags = [t for t in ctx.tags if t in _MEDIUM_SEVERITY_TAGS]
    high_findings = [f for f in ctx.findings if f.severity == "high"]
    if len(medium_tags) + len(high_findings) < 3:
        return False
    max_family = max(ctx.chunks[k].points for k in ("urls", "sender", "urgency", "attachments"))
    return max_family < 45.0


def _auth_sender(ctx: ScoringContext) -> bool:
    return ctx.auth == "any_fail" and ctx.chunks["sender"].points >= 30.0


def _brand_url_cred(ctx: ScoringContext) -> bool:
    return _has(ctx, "brand_url_mismatch") and _has(ctx, "credential_request")


def _archive_invoice_combo(ctx: ScoringContext) -> bool:
    return _has(ctx, "invoice_language") and _has(ctx, "password_protected_archive")


def _ip_cred_combo(ctx: ScoringContext) -> bool:
    return _has(ctx, "ip_literal_host") and (
        _has(ctx, "credential_request") or _has(ctx, "financial_request")
    )


def _external_brand_cred(ctx: ScoringContext) -> bool:
    return _off_domain_link_signal(ctx) and (
        _has(ctx, "brand_url_mismatch") or _has(ctx, "display_name_brand_mismatch")
    )


def _reply_to_payment(ctx: ScoringContext) -> bool:
    if not _has(ctx, "financial_request"):
        return False
    req = ctx.req
    if not req.reply_to:
        return False
    from_dom = domain_from_address(req.from_email)
    reply_dom = domain_from_address(req.reply_to)
    return bool(from_dom and reply_dom and not domains_equal(from_dom, reply_dom))


COMBO_RULES: tuple[ComboRule, ...] = tuple(
    sorted(
        (
            ComboRule(
                "pay_sender_mismatch",
                10,
                20.0,
                "Payment or wire language combined with identity mismatch signals.",
                _pay_sender_mismatch,
            ),
            ComboRule(
                "invoice_malware_attachment",
                12,
                20.0,
                "Payment or invoice wording with executable or double-extension attachment.",
                _invoice_malware_attachment,
            ),
            ComboRule(
                "gift_card_urgency_external",
                14,
                20.0,
                "Gift-card refund pressure with urgency and external or abusive-sender TLD cues.",
                _gift_card_urgency_external,
            ),
            ComboRule(
                "invoice_attachment",
                15,
                20.0,
                "Invoice or remittance wording with a risky archive or macro attachment.",
                _invoice_attachment,
            ),
            ComboRule(
                "archive_invoice_password",
                16,
                18.0,
                "Invoice lure with password-hint archive attachment.",
                _archive_invoice_combo,
            ),
            ComboRule(
                "fake_sec_alert",
                20,
                18.0,
                "Fake security notification with external link and brand impersonation cues.",
                _fake_sec_alert,
            ),
            ComboRule(
                "account_takeover_external",
                22,
                18.0,
                "Account verification or security-alert language with an external login-style link.",
                _account_takeover_external,
            ),
            ComboRule(
                "generic_security_phish",
                24,
                16.0,
                "Generic security-team phrasing with credential language and an external link.",
                _generic_security_phish,
            ),
            ComboRule(
                "cred_external",
                29,
                16.0,
                "Credential request language with links to an external domain.",
                _cred_external,
            ),
            ComboRule(
                "external_brand_cred",
                26,
                16.0,
                "Brand impersonation cues with external login-style links.",
                _external_brand_cred,
            ),
            ComboRule(
                "brand_url_cred",
                27,
                14.0,
                "Credential language with brand-themed URLs on unrelated hosts.",
                _brand_url_cred,
            ),
            ComboRule(
                "otp_login",
                27,
                16.0,
                "OTP or verification-code language with login-like URL paths.",
                _otp_login,
            ),
            ComboRule(
                "bank_urgency",
                35,
                14.0,
                "Payment pressure combined with urgency or security-alert wording.",
                _bank_urgency,
            ),
            ComboRule(
                "ip_cred_combo",
                40,
                14.0,
                "Raw IP link host combined with credential or payment language.",
                _ip_cred_combo,
            ),
            ComboRule(
                "reply_to_payment",
                42,
                14.0,
                "Payment instructions with Reply-To domain drift.",
                _reply_to_payment,
            ),
            ComboRule(
                "auth_sender",
                50,
                12.0,
                "Authentication failure together with suspicious sender signals increased the combined risk score.",
                _auth_sender,
            ),
            ComboRule(
                "weak_signal_stack",
                60,
                12.0,
                "Multiple moderate indicators together exceed isolated single-family risk.",
                _weak_signal_stack,
            ),
        ),
        key=lambda r: r.priority,
    ),
)
