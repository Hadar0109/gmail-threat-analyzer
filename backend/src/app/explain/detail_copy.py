"""Grouped, short copy for the collapsible More details section (presentation only)."""

from __future__ import annotations

from dataclasses import dataclass

from app.explain.synthesis import ResolvedSignal
from app.explain.technical_detail import collect_technical_findings
from app.schemas import MessageAuthentication, ReputationSummary, SignalBreakdown

# Stable strings for tests and HTTP clients that assert link deduplication.
LINK_NON_SECURE = "Non-HTTPS link detected"
LINK_OFF_DOMAIN = "Link host is outside the sender From domain"

_GROUP_ORDER: tuple[tuple[str, str], ...] = (
    ("authentication", "Authentication"),
    ("sender_identity", "Sender identity"),
    ("links", "Links"),
    ("attachments", "Attachments"),
    ("reputation", "Reputation"),
    ("signal_scores", "Signal scores"),
)


@dataclass(frozen=True, slots=True)
class DetailGroup:
    group_id: str
    label: str
    items: tuple[str, ...]


def build_detail_groups(
    resolved: list[ResolvedSignal],
    technical_reasons: list[str],
    *,
    reputation: ReputationSummary | None,
    authentication: MessageAuthentication | None,
    signals: SignalBreakdown | None,
) -> tuple[DetailGroup, ...]:
    """Build filtered, deduplicated detail groups for the add-on."""
    grouped = collect_technical_findings(
        resolved,
        technical_reasons,
        reputation=reputation,
        authentication=authentication,
    )
    signal_items = _signal_items(signals)
    if signal_items:
        grouped["signal_scores"] = signal_items

    groups: list[DetailGroup] = []
    for group_id, label in _GROUP_ORDER:
        items = grouped.get(group_id)
        if items:
            groups.append(DetailGroup(group_id, label, items))
    return tuple(groups)


def _signal_items(signals: SignalBreakdown | None) -> tuple[str, ...]:
    if signals is None:
        return ()

    pairs = (
        ("Headers", signals.headers),
        ("Sender", signals.sender),
        ("Links", signals.urls),
        ("Message content", signals.urgency),
        ("Attachments", signals.attachments),
        ("Link reputation", signals.reputation_overlay),
    )
    out: list[str] = []
    for label, value in pairs:
        score = int(round(value))
        if score > 0:
            out.append(f"{label}: {score}")
    return tuple(out)
