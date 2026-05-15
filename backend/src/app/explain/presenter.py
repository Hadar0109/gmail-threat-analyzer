"""Assemble structured explanations for API responses."""

from __future__ import annotations

from collections import defaultdict

from app.explain.brief_copy import select_brief_sentences
from app.explain.detail_copy import build_detail_groups
from app.explain.resolver import resolve_reason
from app.explain.synthesis import ResolvedSignal, classify_signal, synthesize_findings
from app.explain.types import CATEGORY_DISPLAY_ORDER, CATEGORY_LABELS
from app.schemas import (
    ExplanationDetailGroup,
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


def build_score_explanation(
    technical_reasons: list[str],
    verdict: Verdict,
    *,
    signals: SignalBreakdown | None = None,
    reputation: ReputationSummary | None = None,
    reputation_notice: str = "",
    authentication: MessageAuthentication | None = None,
) -> ScoreExplanation:
    """Convert ranked internal reasons into main-card brief copy + grouped details."""
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
    detail_groups = [
        ExplanationDetailGroup(
            group_id=g.group_id,
            label=g.label,
            items=list(g.items),
        )
        for g in build_detail_groups(
            resolved,
            technical_reasons,
            reputation=reputation,
            authentication=authentication,
            signals=signals,
        )
    ]

    guidance = VerdictGuidance(
        summary=_VERDICT_SUMMARIES[verdict],
        recommended_action=_VERDICT_ACTIONS[verdict],
    )

    return ScoreExplanation(
        brief_sentences=brief,
        verdict_guidance=guidance,
        key_findings=list(synthesis.key_findings),
        detail_groups=detail_groups,
        detail_sections=[],
        items=list(synthesis.all_items),
        groups=_build_groups(list(synthesis.all_items)),
        reasons=brief,
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
