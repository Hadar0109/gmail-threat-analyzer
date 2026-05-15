"""Assemble structured explanations for API responses."""

from __future__ import annotations

from collections import defaultdict

from app.explain.resolver import resolve_reason
from app.explain.types import CATEGORY_DISPLAY_ORDER, CATEGORY_LABELS, ExplanationCategory
from app.schemas import (
    ExplanationGroup,
    ExplanationItem,
    ScoreExplanation,
    Verdict,
    VerdictGuidance,
)

_VERDICT_SUMMARIES: dict[Verdict, str] = {
    Verdict.SAFE: "This email appears legitimate based on the checks performed.",
    Verdict.SUSPICIOUS: "Some parts of this email look unusual. Review carefully before interacting.",
    Verdict.DANGEROUS: "This email shows multiple warning signs commonly seen in phishing attempts.",
    Verdict.CRITICAL: "This message is highly likely to be malicious or impersonating a trusted source.",
}

_VERDICT_ACTIONS: dict[Verdict, str] = {
    Verdict.SAFE: "You can read this message normally, but stay cautious with unexpected links or attachments.",
    Verdict.SUSPICIOUS: "Avoid clicking links or opening attachments until you confirm who sent this.",
    Verdict.DANGEROUS: "Do not click links, open attachments, or share personal information until you verify the sender.",
    Verdict.CRITICAL: "Do not interact with this message. Delete it or report it as phishing if you are unsure.",
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_score_explanation(
    technical_reasons: list[str],
    verdict: Verdict,
) -> ScoreExplanation:
    """Convert ranked internal reasons into structured, user-facing explanations."""
    items: list[ExplanationItem] = []
    seen_messages: set[str] = set()

    for technical in technical_reasons:
        spec = resolve_reason(technical)
        if spec.message in seen_messages:
            continue
        seen_messages.add(spec.message)
        items.append(
            ExplanationItem(
                category=spec.category.value,
                category_label=CATEGORY_LABELS[spec.category],
                severity=spec.severity.value,
                message=spec.message,
                guidance=spec.guidance,
            ),
        )

    groups = _build_groups(items)
    guidance = VerdictGuidance(
        summary=_VERDICT_SUMMARIES[verdict],
        recommended_action=_VERDICT_ACTIONS[verdict],
    )
    human_reasons = [item.message for item in items]
    if not human_reasons:
        human_reasons = [
            _VERDICT_SUMMARIES[verdict],
            _VERDICT_ACTIONS[verdict],
        ]

    return ScoreExplanation(
        verdict_guidance=guidance,
        items=items,
        groups=groups,
        reasons=human_reasons,
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
