"""Assemble structured explanations for API responses."""

from __future__ import annotations

from collections import defaultdict

from app.explain.resolver import resolve_reason
from app.explain.synthesis import ResolvedSignal, classify_signal, synthesize_findings
from app.explain.types import CATEGORY_DISPLAY_ORDER, CATEGORY_LABELS, ExplanationCategory
from app.schemas import (
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
    Verdict.SAFE: "This email looks fine based on our checks.",
    Verdict.SUSPICIOUS: "A few things about this email looked unusual. Take a quick look before you reply or click anything.",
    Verdict.DANGEROUS: "This email has several warning signs that are common in phishing messages.",
    Verdict.CRITICAL: "This email is very likely unsafe. We recommend not interacting with it.",
}

_VERDICT_ACTIONS: dict[Verdict, str] = {
    Verdict.SAFE: "You can read this message as usual. If anything still feels off, double-check the sender before clicking links.",
    Verdict.SUSPICIOUS: "Avoid clicking links or opening attachments until you are sure who sent this.",
    Verdict.DANGEROUS: "Do not click links, open attachments, or share personal details until you verify the sender.",
    Verdict.CRITICAL: "Do not reply, click links, or open attachments. Delete the message or report it as phishing if you are unsure.",
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_score_explanation(
    technical_reasons: list[str],
    verdict: Verdict,
    *,
    signals: SignalBreakdown | None = None,
    reputation: ReputationSummary | None = None,
    reputation_notice: str = "",
    authentication: MessageAuthentication | None = None,
) -> ScoreExplanation:
    """Convert ranked internal reasons into synthesized, consumer-friendly explanations."""
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

    guidance = VerdictGuidance(
        summary=_VERDICT_SUMMARIES[verdict],
        recommended_action=_VERDICT_ACTIONS[verdict],
    )

    key_messages = [f.message for f in synthesis.key_findings]
    reasons = key_messages if key_messages else [guidance.summary]

    return ScoreExplanation(
        verdict_guidance=guidance,
        key_findings=list(synthesis.key_findings),
        detail_sections=list(synthesis.detail_sections),
        items=list(synthesis.all_items),
        groups=_build_groups(list(synthesis.all_items)),
        reasons=reasons[:5],
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
