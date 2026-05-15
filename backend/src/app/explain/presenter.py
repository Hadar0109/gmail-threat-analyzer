"""Assemble structured explanations for API responses."""

from __future__ import annotations

from collections import defaultdict

from app.explain.brief_copy import CHECKED_NOTICE, SENTENCE_LIBRARY, select_brief_sentences
from app.explain.resolver import resolve_reason
from app.explain.synthesis import ResolvedSignal, classify_signal, synthesize_findings
from app.explain.types import (
    CATEGORY_DISPLAY_ORDER,
    CATEGORY_LABELS,
    DisplayTier,
    SynthesisTheme,
)
from app.schemas import (
    ExplanationDetailSection,
    ExplanationGroup,
    ExplanationItem,
    MessageAuthentication,
    ReputationSummary,
    ScoreExplanation,
    SignalBreakdown,
    Verdict,
    VerdictGuidance,
)

_VERDICT_SUMMARIES: dict[Verdict, str] = {
    Verdict.SAFE: "No major concerns were found.",
    Verdict.SUSPICIOUS: "A few things looked unusual.",
    Verdict.DANGEROUS: "Several warning signs were found.",
    Verdict.CRITICAL: "Strong warning signs were found.",
}

_VERDICT_ACTIONS: dict[Verdict, str] = {
    Verdict.SAFE: "You can read this message as usual.",
    Verdict.SUSPICIOUS: "Confirm the sender before clicking links or opening attachments.",
    Verdict.DANGEROUS: "Avoid links and attachments until you verify the sender.",
    Verdict.CRITICAL: "Do not interact with this message if you are unsure who sent it.",
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_MORE_DETAILS_LABEL = "More details"


def build_score_explanation(
    technical_reasons: list[str],
    verdict: Verdict,
    *,
    signals: SignalBreakdown | None = None,
    reputation: ReputationSummary | None = None,
    reputation_notice: str = "",
    authentication: MessageAuthentication | None = None,
) -> ScoreExplanation:
    """Convert ranked internal reasons into main-card brief copy + collapsible details."""
    resolved: list[ResolvedSignal] = []
    for technical in technical_reasons:
        spec = resolve_reason(technical)
        resolved.append(classify_signal(technical, spec))

    synthesis = synthesize_findings(
        resolved,
        verdict=verdict,
        signals=signals,
        reputation=reputation,
        reputation_notice=reputation_notice,
        authentication=authentication,
    )

    brief = select_brief_sentences(resolved, verdict=verdict)
    more_details = _build_more_details(
        resolved,
        synthesis.detail_sections,
        technical_reasons,
        reputation_notice=reputation_notice,
        reputation=reputation,
        signals=signals,
        authentication=authentication,
    )

    guidance = VerdictGuidance(
        summary=_VERDICT_SUMMARIES[verdict],
        recommended_action=_VERDICT_ACTIONS[verdict],
    )

    detail_sections = [more_details] if more_details.items else []

    return ScoreExplanation(
        checked_notice=CHECKED_NOTICE,
        brief_sentences=brief,
        verdict_guidance=guidance,
        key_findings=list(synthesis.key_findings),
        detail_sections=detail_sections,
        items=list(synthesis.all_items),
        groups=_build_groups(list(synthesis.all_items)),
        reasons=brief,
    )


def _build_more_details(
    resolved: list[ResolvedSignal],
    existing_sections: tuple[ExplanationDetailSection, ...],
    technical_reasons: list[str],
    *,
    reputation_notice: str,
    reputation: ReputationSummary | None,
    signals: SignalBreakdown | None,
    authentication: MessageAuthentication | None,
) -> ExplanationDetailSection:
    """Single expandable block with technical/detector-level copy only."""
    items: list[ExplanationItem] = []
    seen: set[str] = set()

    def add_technical(text: str, *, category: str = "technical") -> None:
        t = text.strip()
        if not t or t in seen:
            return
        seen.add(t)
        items.append(
            ExplanationItem(
                category=category,
                category_label="Technical",
                severity="low",
                message=t,
                guidance=None,
            ),
        )

    for row in resolved:
        if row.tier == DisplayTier.TECHNICAL or row.theme in (
            SynthesisTheme.AUTH_CHECK,
            SynthesisTheme.TECHNICAL_DETAIL,
        ):
            add_technical(row.technical, category="authentication" if row.theme == SynthesisTheme.AUTH_CHECK else "technical")

    for technical in technical_reasons:
        lower = technical.lower()
        if any(k in lower for k in ("spf", "dkim", "dmarc")):
            add_technical(technical, category="authentication")

    if authentication is not None:
        for label, raw in (("SPF", authentication.spf), ("DKIM", authentication.dkim), ("DMARC", authentication.dmarc)):
            if raw and str(raw).strip():
                add_technical(f"{label}: {str(raw).strip().lower()}", category="authentication")

    if reputation_notice:
        add_technical(reputation_notice, category="reputation_warnings")
    if reputation and reputation.providers:
        for name, status in reputation.providers.items():
            label = "Google Safe Browsing" if name == "safe_browsing" else "VirusTotal"
            add_technical(f"{label}: {status}", category="reputation_warnings")

    for section in existing_sections:
        for item in section.items:
            if item.message not in seen:
                seen.add(item.message)
                items.append(item)

    if signals is not None:
        add_technical(
            f"Signal scores — headers: {int(signals.headers)}, sender: {int(signals.sender)}, "
            f"links: {int(signals.urls)}, content: {int(signals.urgency)}, "
            f"attachments: {int(signals.attachments)}, reputation overlay: {int(signals.reputation_overlay)}",
            category="signals",
        )

    return ExplanationDetailSection(
        section_id="more_details",
        label=_MORE_DETAILS_LABEL,
        items=items[:24],
    )


def _build_groups(items: list[ExplanationItem]) -> list[ExplanationGroup]:
    by_category: dict[str, list[ExplanationItem]] = defaultdict(list)
    for item in items:
        by_category[item.category].append(item)

    groups: list[ExplanationGroup] = []
    for category in CATEGORY_DISPLAY_ORDER:
        cat_key = category.value
        group_items = by_category.get(cat_key)
        if not group_items:
            continue
        group_items.sort(
            key=lambda i: _SEVERITY_RANK.get(i.severity, 0),
            reverse=True,
        )
        groups.append(
            ExplanationGroup(
                category=cat_key,
                label=CATEGORY_LABELS[category],
                items=group_items,
            ),
        )
    return groups
