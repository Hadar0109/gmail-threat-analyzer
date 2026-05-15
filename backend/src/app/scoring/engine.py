"""Scoring engine entrypoint — orchestration only (Layer 3 in aggregate.py)."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.limits import LIMITS
from app.reputation.providers import run_reputation_checks
from app.schemas import (
    ReputationSummary,
    ScoreRequest,
    ScoreResponse,
    SignalBreakdown,
    verdict_from_score,
)
from app.scoring.aggregate import (
    apply_critical_cap_for_urgency_isolation as _apply_critical_cap,
    apply_critical_cap_for_urgency_isolation_legacy,
    apply_reputation_floor,
    compose_reasons,
    confidence_from_signals,
    dampen_urgency_for_trusted_auth,
    reputation_notice_text,
    sender_breakdown_points,
    weighted_non_urgency_and_urgency,
)
from app.scoring.combos.context import auth_band, build_scoring_context
from app.scoring.combos.evaluator import evaluate_combos
from app.scoring.features.extract import MessageFeatures
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals_attachments import evaluate_attachments
from app.scoring.signals_headers import evaluate_headers
from app.scoring.signals_sender import evaluate_sender
from app.scoring.signals_urgency import evaluate_urgency
from app.scoring.signals_urls import evaluate_urls
from app.scoring.types import SignalChunk

# Tests pass raw family points; production uses weighted chunk-based cap.
apply_critical_cap_for_urgency_isolation = apply_critical_cap_for_urgency_isolation_legacy


def score_message(req: ScoreRequest) -> ScoreResponse:
    """Run local heuristics, optional reputation, combination rules, and verdict mapping."""
    _ = MessageFeatures.from_request(req)
    rep = run_reputation_checks(req.urls)

    brand_chunk, brand_findings = evaluate_brand_impersonation(req)

    chunks: dict[str, SignalChunk] = {
        "headers": evaluate_headers(req),
        "sender": evaluate_sender(req),
        "brand": brand_chunk,
        "urls": evaluate_urls(req),
        "urgency": evaluate_urgency(req),
        "attachments": evaluate_attachments(req),
        "reputation_overlay": SignalChunk(rep.overlay_points, rep.reasons),
    }

    auth = auth_band(req)
    chunks["urgency"], urgency_dampened = dampen_urgency_for_trusted_auth(chunks, auth)

    non_urgency, urgency_weighted = weighted_non_urgency_and_urgency(chunks)
    total = non_urgency + urgency_weighted

    ctx = build_scoring_context(req, chunks, brand_findings=brand_findings)
    combo = evaluate_combos(ctx)
    total = min(100.0, total + combo.boost)

    total, reputation_floor = apply_reputation_floor(total, rep)

    total, critical_capped = _apply_critical_cap(
        total,
        rep=rep,
        chunks=chunks,
    )

    score = int(round(min(100.0, total)))
    reasons = compose_reasons(
        chunks,
        limit=LIMITS.MAX_REASONS,
        auth=auth,
        urgency_dampened=urgency_dampened,
        reputation_floor=reputation_floor,
        critical_capped=critical_capped,
        combo_reasons=combo.reasons,
    )
    confidence = confidence_from_signals(req, chunks, rep, auth)

    return ScoreResponse(
        schema_version=SCHEMA_VERSION,
        score=score,
        verdict=verdict_from_score(score),
        confidence=confidence,
        reasons=reasons,
        signals=SignalBreakdown(
            headers=chunks["headers"].points,
            sender=sender_breakdown_points(chunks),
            urls=chunks["urls"].points,
            urgency=chunks["urgency"].points,
            attachments=chunks["attachments"].points,
            reputation_overlay=chunks["reputation_overlay"].points,
        ),
        reputation=ReputationSummary(contributed=rep.contributed, providers=rep.providers),
        reputation_notice=reputation_notice_text(rep.notice_kind),
    )
