"""Aggregation unit tests.

Responsible for verifying weighted merge, caps, and family math in aggregate.py.
"""

from __future__ import annotations

from app.reputation.providers import ReputationRunResult
from app.scoring.aggregate import (
    aggregate_attachment_scores,
    aggregate_max_plus_fraction,
    aggregate_url_structural,
    apply_critical_cap_for_urgency_isolation,
    points_from_attachment_findings,
    weighted_non_urgency_and_urgency,
)
from app.scoring.weights import FAMILY_WEIGHTS
from app.scoring.types import Finding, SignalChunk


def test_family_weights_sum_to_one() -> None:
    assert abs(sum(FAMILY_WEIGHTS.values()) - 1.0) < 1e-6


def test_url_soft_stack_caps_at_eighteen() -> None:
    assert aggregate_url_structural(40.0, 4) == 58.0
    assert aggregate_url_structural(40.0, 10) == 58.0


def test_attachment_max_plus_fraction() -> None:
    scores = [42.0, 26.0, 12.0]
    got = aggregate_max_plus_fraction(scores, secondary_factor=0.35)
    assert got == 42.0 + (26.0 + 12.0) * 0.35


def test_attachment_high_severity_stacks() -> None:
    got = aggregate_attachment_scores([42.0, 42.0, 26.0])
    assert got > 42.0


def test_points_from_attachment_findings_empty() -> None:
    assert points_from_attachment_findings(()) == 0.0


def test_weighted_blend_uses_sender_brand_identity() -> None:
    chunks = {
        "headers": SignalChunk(6.0),
        "sender": SignalChunk(20.0),
        "brand": SignalChunk(50.0),
        "urls": SignalChunk(0.0),
        "urgency": SignalChunk(0.0),
        "attachments": SignalChunk(0.0),
        "reputation_overlay": SignalChunk(0.0),
    }
    nu, urg = weighted_non_urgency_and_urgency(chunks)
    assert nu > FAMILY_WEIGHTS["sender"] * 20.0
    assert urg == 0.0


def test_critical_cap_uses_weighted_contributions() -> None:
    rep = ReputationRunResult(
        overlay_points=0.0,
        reasons=(),
        contributed=False,
        providers={"safe_browsing": "skipped_no_api_key", "virustotal": "skipped_no_api_key"},
        notice_kind="local_only",
    )
    chunks = {
        "urgency": SignalChunk(60.0),
        "urls": SignalChunk(5.0),
        "sender": SignalChunk(10.0),
        "brand": SignalChunk(0.0),
        "headers": SignalChunk(0.0),
        "attachments": SignalChunk(0.0),
        "reputation_overlay": SignalChunk(0.0),
    }
    total, capped = apply_critical_cap_for_urgency_isolation(80.0, rep=rep, chunks=chunks)
    assert capped is True
    assert total == 77.0


def test_critical_cap_finding_severity_points() -> None:
    findings = (
        Finding(tag="t", severity="high", reason="r"),
        Finding(tag="u", severity="low", reason="s"),
    )
    from app.scoring.aggregate import points_from_findings

    assert points_from_findings(findings, structural_best=10.0) == 42.0
