"""Synthesize many detector signals into a small set of user-facing findings.

Groups related signals, deduplicates, rebalances severity, and splits main vs technical.
Does not alter scores or detector output.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.explain.registry import ExplanationSpec
from app.explain.types import (
    DisplayTier,
    ExplanationCategory,
    ExplanationSeverity,
    MAX_KEY_FINDINGS,
    SynthesisTheme,
)
from app.schemas import (
    ExplanationDetailSection,
    ExplanationItem,
    KeyFinding,
    MessageAuthentication,
    ReputationSummary,
    SignalBreakdown,
    Verdict,
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_THEME_PRIORITY: dict[SynthesisTheme, int] = {
    SynthesisTheme.MALICIOUS_LINK: 100,
    SynthesisTheme.DANGEROUS_ATTACHMENT: 95,
    SynthesisTheme.SENDER_TRUST: 85,
    SynthesisTheme.SUSPICIOUS_SIGN_IN: 80,
    SynthesisTheme.PAYMENT_SENSITIVE: 75,
    SynthesisTheme.PRESSURE_TACTICS: 50,
    SynthesisTheme.DELIVERY_SCAM: 48,
    SynthesisTheme.GENERAL_CAUTION: 30,
    SynthesisTheme.AUTH_CHECK: 15,
    SynthesisTheme.TECHNICAL_DETAIL: 10,
}

_THEME_COPY: dict[SynthesisTheme, tuple[str, str | None, str]] = {
    SynthesisTheme.MALICIOUS_LINK: (
        "A link in this email has been reported as unsafe.",
        "Avoid clicking links or opening files from this message.",
        "critical",
    ),
    SynthesisTheme.DANGEROUS_ATTACHMENT: (
        "An attachment in this message may be unsafe to open.",
        "Only open attachments you expected from someone you trust.",
        "critical",
    ),
    SynthesisTheme.SENDER_TRUST: (
        "The sender does not appear to match who this message claims to be from.",
        "Confirm who sent this before replying or clicking anything.",
        "high",
    ),
    SynthesisTheme.SUSPICIOUS_SIGN_IN: (
        "This email contains a suspicious sign-in link that may lead to another website.",
        "Sign in through the official website or app instead of a link in the email.",
        "high",
    ),
    SynthesisTheme.PAYMENT_SENSITIVE: (
        "The message asks for payment, credentials, or other sensitive information.",
        "Verify payment or personal-information requests through a trusted contact method.",
        "high",
    ),
    SynthesisTheme.PRESSURE_TACTICS: (
        "This email tries to create pressure by mentioning account problems or tight deadlines.",
        "Take a moment to verify before acting on urgent requests.",
        "medium",
    ),
    SynthesisTheme.DELIVERY_SCAM: (
        "This message resembles a delivery or fee notice that is often used in scams.",
        "Check tracking or fees on the carrier's official website.",
        "medium",
    ),
    SynthesisTheme.GENERAL_CAUTION: (
        "A few things about this message looked unusual during our review.",
        "Review the sender and any links before interacting.",
        "medium",
    ),
    SynthesisTheme.AUTH_CHECK: (
        "Sender verification checks were incomplete or did not fully pass.",
        None,
        "low",
    ),
    SynthesisTheme.TECHNICAL_DETAIL: (
        "Additional technical checks contributed to the overall score.",
        None,
        "low",
    ),
}


@dataclass(frozen=True, slots=True)
class ResolvedSignal:
    technical: str
    spec: ExplanationSpec
    theme: SynthesisTheme
    tier: DisplayTier


def classify_signal(technical: str, spec: ExplanationSpec) -> ResolvedSignal:
    """Assign a synthesis theme and display tier from the internal reason text."""
    t = technical.lower()
    theme = SynthesisTheme.GENERAL_CAUTION
    tier = DisplayTier.MAIN

    if "safe browsing" in t or (
        "virustotal" in t and ("malicious" in t or "elevated suspicious" in t)
    ):
        return ResolvedSignal(technical, spec, SynthesisTheme.MALICIOUS_LINK, DisplayTier.MAIN)

    if any(
        k in t
        for k in (
            "executable attachment",
            "double extension",
            "password-protected archive",
            "password-hint archive",
            "macro-enabled office",
        )
    ):
        return ResolvedSignal(technical, spec, SynthesisTheme.DANGEROUS_ATTACHMENT, DisplayTier.MAIN)

    if any(
        k in t
        for k in (
            "reply-to domain",
            "display name references",
            "closely resembles",
            "confusable characters",
            "punycode/idn",
            "brand-like label",
            "corporate-style display name",
            "not on an official domain",
            "authorized",
            "impersonation",
            "authentication failure together",
        )
    ):
        return ResolvedSignal(technical, spec, SynthesisTheme.SENDER_TRUST, DisplayTier.MAIN)

    if _matches_sign_in_cluster(t, spec):
        return ResolvedSignal(technical, spec, SynthesisTheme.SUSPICIOUS_SIGN_IN, DisplayTier.MAIN)

    if (
        any(
            k in t
            for k in (
                "wire transfer",
                "bank account",
                "payment or transfer",
                "social security",
                "government id",
                "payroll",
                "tax document",
                "gift card",
                "cryptocurrency",
                "prepaid card",
                "one-time code",
                "verification code",
                "2fa",
                "mfa",
                "credential request",
                "payment instructions",
                "remittance",
            )
        )
        or ("invoice" in t and "payment" in t)
        or spec.category == ExplanationCategory.SENSITIVE_REQUESTS
    ):
        if spec.severity in (ExplanationSeverity.HIGH, ExplanationSeverity.CRITICAL) or any(
            k in t for k in ("wire", "ssn", "password", "credential", "otp", "2fa", "gift card")
        ):
            return ResolvedSignal(technical, spec, SynthesisTheme.PAYMENT_SENSITIVE, DisplayTier.MAIN)

    if any(
        k in t
        for k in (
            "package is held",
            "customs",
            "tracking",
            "failed-delivery",
            "delivery",
        )
    ):
        return ResolvedSignal(technical, spec, SynthesisTheme.DELIVERY_SCAM, DisplayTier.MAIN)

    if spec.category == ExplanationCategory.URGENCY_PRESSURE:
        return ResolvedSignal(technical, spec, SynthesisTheme.PRESSURE_TACTICS, DisplayTier.MAIN)

    if any(k in t for k in ("spf", "dkim", "dmarc", "authentication")):
        return ResolvedSignal(technical, spec, SynthesisTheme.AUTH_CHECK, DisplayTier.TECHNICAL)

    if spec.severity == ExplanationSeverity.LOW or any(
        k in t
        for k in (
            "http instead of https",
            "no spf/dkim/dmarc summary",
            "all reported pass",
            "neutral",
            " weighted more cautiously",
            "peak severity was limited",
            "trusted transactional",
            "no strong risk patterns",
            "review links and sender context manually",
            "multiple moderate indicators",
        )
    ):
        return ResolvedSignal(technical, spec, SynthesisTheme.TECHNICAL_DETAIL, DisplayTier.TECHNICAL)

    if spec.category == ExplanationCategory.LINKS_WEBSITES:
        if any(
            k in t
            for k in (
                "login",
                "credential",
                "ip address",
                "shortener",
                "punycode",
                "nested http",
                "high-risk url",
            )
        ):
            return ResolvedSignal(technical, spec, SynthesisTheme.SUSPICIOUS_SIGN_IN, DisplayTier.MAIN)
        if "outside the sender domain" in t or "off-domain links" in t:
            return ResolvedSignal(technical, spec, SynthesisTheme.TECHNICAL_DETAIL, DisplayTier.TECHNICAL)

    if spec.category == ExplanationCategory.REPUTATION and spec.severity != ExplanationSeverity.CRITICAL:
        return ResolvedSignal(technical, spec, SynthesisTheme.MALICIOUS_LINK, DisplayTier.MAIN)

    if spec.category == ExplanationCategory.ATTACHMENTS:
        return ResolvedSignal(technical, spec, SynthesisTheme.DANGEROUS_ATTACHMENT, DisplayTier.MAIN)

    if spec.category == ExplanationCategory.SYSTEM:
        return ResolvedSignal(technical, spec, SynthesisTheme.TECHNICAL_DETAIL, DisplayTier.TECHNICAL)

    return ResolvedSignal(technical, spec, theme, tier)


def _matches_sign_in_cluster(t: str, spec: ExplanationSpec) -> bool:
    if spec.category == ExplanationCategory.SENSITIVE_REQUESTS and any(
        k in t for k in ("verify", "password", "sign in", "login", "credential", "session")
    ):
        return True
    return any(
        k in t
        for k in (
            "login-like",
            "login or verification",
            "credential request",
            "otp or verification",
            "account verification",
            "sign-in link",
            "external login",
            "brand-themed urls",
            "nested http",
            "credential path",
        )
    )


def _rebalance_severity(theme: SynthesisTheme, verdict: Verdict, *, has_malicious_link: bool) -> str:
    """Reserve critical for strong indicators; keep the main card calm but accurate."""
    _, _, default = _THEME_COPY[theme]
    if theme == SynthesisTheme.MALICIOUS_LINK:
        return "critical"
    if theme == SynthesisTheme.DANGEROUS_ATTACHMENT:
        return "critical"
    if theme == SynthesisTheme.PAYMENT_SENSITIVE and has_malicious_link:
        return "critical"
    if theme in (SynthesisTheme.SENDER_TRUST, SynthesisTheme.SUSPICIOUS_SIGN_IN, SynthesisTheme.PAYMENT_SENSITIVE):
        if verdict == Verdict.CRITICAL and theme == SynthesisTheme.SUSPICIOUS_SIGN_IN:
            return "high"
        return default
    if theme in (SynthesisTheme.PRESSURE_TACTICS, SynthesisTheme.DELIVERY_SCAM, SynthesisTheme.GENERAL_CAUTION):
        return "medium"
    return default


@dataclass(frozen=True, slots=True)
class SynthesisResult:
    key_findings: tuple[KeyFinding, ...]
    detail_sections: tuple[ExplanationDetailSection, ...]
    all_items: tuple[ExplanationItem, ...]


def synthesize_findings(
    resolved: list[ResolvedSignal],
    *,
    verdict: Verdict,
    signals: SignalBreakdown | None = None,
    reputation: ReputationSummary | None = None,
    reputation_notice: str = "",
    authentication: MessageAuthentication | None = None,
) -> SynthesisResult:
    """Merge related signals into key findings and collapsible detail sections."""
    by_theme: dict[SynthesisTheme, list[ResolvedSignal]] = {}
    for row in resolved:
        by_theme.setdefault(row.theme, []).append(row)

    has_malicious = SynthesisTheme.MALICIOUS_LINK in by_theme
    main_themes = [th for th in by_theme if _THEME_PRIORITY[th] >= _THEME_PRIORITY[SynthesisTheme.GENERAL_CAUTION]]

    main_themes.sort(key=lambda th: _THEME_PRIORITY[th], reverse=True)
    key_findings: list[KeyFinding] = []
    used_themes: set[SynthesisTheme] = set()

    for theme in main_themes:
        if theme in (SynthesisTheme.AUTH_CHECK, SynthesisTheme.TECHNICAL_DETAIL):
            continue
        if len(key_findings) >= MAX_KEY_FINDINGS:
            break
        if theme in used_themes:
            continue
        message, guidance, _ = _THEME_COPY[theme]
        severity = _rebalance_severity(theme, verdict, has_malicious_link=has_malicious)
        key_findings.append(
            KeyFinding(
                message=message,
                severity=severity,
                guidance=guidance,
                theme=theme.value,
            ),
        )
        used_themes.add(theme)

    if not key_findings and verdict != Verdict.SAFE:
        for theme in (SynthesisTheme.GENERAL_CAUTION,):
            if theme in by_theme:
                message, guidance, severity = _THEME_COPY[theme]
                key_findings.append(
                    KeyFinding(message=message, severity=severity, guidance=guidance, theme=theme.value),
                )
                break

    all_items = _all_explanation_items(resolved)
    detail_sections = _build_detail_sections(
        resolved,
        by_theme,
        used_themes,
        signals=signals,
        reputation=reputation,
        reputation_notice=reputation_notice,
        authentication=authentication,
    )

    return SynthesisResult(
        key_findings=tuple(key_findings),
        detail_sections=tuple(detail_sections),
        all_items=tuple(all_items),
    )


def _all_explanation_items(resolved: list[ResolvedSignal]) -> list[ExplanationItem]:
    from app.explain.types import CATEGORY_LABELS

    items: list[ExplanationItem] = []
    seen: set[str] = set()
    for row in resolved:
        if row.spec.message in seen:
            continue
        seen.add(row.spec.message)
        items.append(
            ExplanationItem(
                category=row.spec.category.value,
                category_label=CATEGORY_LABELS[row.spec.category],
                severity=row.spec.severity.value,
                message=row.spec.message,
                guidance=row.spec.guidance,
            ),
        )
    return items


def _build_detail_sections(
    resolved: list[ResolvedSignal],
    by_theme: dict[SynthesisTheme, list[ResolvedSignal]],
    main_themes: set[SynthesisTheme],
    *,
    signals: SignalBreakdown | None,
    reputation: ReputationSummary | None,
    reputation_notice: str,
    authentication: MessageAuthentication | None,
) -> list[ExplanationDetailSection]:
    from app.explain.types import CATEGORY_LABELS

    sections: list[ExplanationDetailSection] = []

    auth_items: list[ExplanationItem] = []
    for row in by_theme.get(SynthesisTheme.AUTH_CHECK, []):
        auth_items.append(_row_to_item(row))
    if authentication is not None:
        for label, raw in (("SPF", authentication.spf), ("DKIM", authentication.dkim), ("DMARC", authentication.dmarc)):
            if raw and str(raw).strip():
                auth_items.append(
                    ExplanationItem(
                        category="authentication",
                        category_label="Authentication",
                        severity="low",
                        message=f"{label} result: {str(raw).strip().lower()}",
                        guidance=None,
                    ),
                )
    if auth_items:
        sections.append(
            ExplanationDetailSection(
                section_id="authentication",
                label="Authentication checks",
                items=_dedupe_items(auth_items),
            ),
        )

    technical: list[ExplanationItem] = []
    for row in resolved:
        if row.tier == DisplayTier.TECHNICAL or row.theme == SynthesisTheme.TECHNICAL_DETAIL:
            technical.append(_row_to_item(row))
        elif row.theme not in main_themes and row.theme not in (
            SynthesisTheme.AUTH_CHECK,
        ):
            technical.append(_row_to_item(row))
    if technical:
        sections.append(
            ExplanationDetailSection(
                section_id="technical_details",
                label="Technical details",
                items=_dedupe_items(technical)[:12],
            ),
        )

    if reputation is not None or reputation_notice:
        rep_items: list[ExplanationItem] = []
        if reputation_notice:
            rep_items.append(
                ExplanationItem(
                    category="reputation_warnings",
                    category_label=CATEGORY_LABELS[ExplanationCategory.REPUTATION],
                    severity="low",
                    message=reputation_notice,
                    guidance=None,
                ),
            )
        if reputation and reputation.providers:
            for name, status in reputation.providers.items():
                label = "Google Safe Browsing" if name == "safe_browsing" else "VirusTotal"
                rep_items.append(
                    ExplanationItem(
                        category="reputation_warnings",
                        category_label=CATEGORY_LABELS[ExplanationCategory.REPUTATION],
                        severity="low",
                        message=f"{label}: {status}",
                        guidance=None,
                    ),
                )
        if rep_items:
            sections.append(
                ExplanationDetailSection(
                    section_id="reputation",
                    label="Link safety checks",
                    items=rep_items,
                ),
            )

    if signals is not None:
        signal_items = [
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Headers: {int(signals.headers)}",
                guidance=None,
            ),
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Sender: {int(signals.sender)}",
                guidance=None,
            ),
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Links: {int(signals.urls)}",
                guidance=None,
            ),
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Message content: {int(signals.urgency)}",
                guidance=None,
            ),
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Attachments: {int(signals.attachments)}",
                guidance=None,
            ),
            ExplanationItem(
                category="signals",
                category_label="Signal breakdown",
                severity="low",
                message=f"Link reputation overlay: {int(signals.reputation_overlay)}",
                guidance=None,
            ),
        ]
        sections.append(
            ExplanationDetailSection(
                section_id="signals",
                label="Signal breakdown",
                items=signal_items,
            ),
        )

    return sections


def _row_to_item(row: ResolvedSignal) -> ExplanationItem:
    from app.explain.types import CATEGORY_LABELS

    return ExplanationItem(
        category=row.spec.category.value,
        category_label=CATEGORY_LABELS[row.spec.category],
        severity=row.spec.severity.value,
        message=row.spec.message,
        guidance=row.spec.guidance,
    )


def _dedupe_items(items: list[ExplanationItem]) -> list[ExplanationItem]:
    seen: set[str] = set()
    out: list[ExplanationItem] = []
    for item in items:
        if item.message in seen:
            continue
        seen.add(item.message)
        out.append(item)
    return out
