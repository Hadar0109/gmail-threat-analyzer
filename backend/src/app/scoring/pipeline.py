"""Scoring pipeline orchestration.

Responsible for coordinating reputation, signal evaluation, combos, caps, and response assembly.
Does not define individual detector rules.
"""
from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.explain import build_score_explanation
from app.limits import LIMITS
from app.reputation.providers import ReputationRunResult, run_reputation_checks
from app.schemas import (
    ReputationSummary,
    ScoreRequest,
    ScoreResponse,
    SignalBreakdown,
    verdict_from_score,
)
from app.scoring.aggregate import (
    apply_critical_cap_for_urgency_isolation,
    apply_reputation_floor,
    compose_reasons,
    confidence_from_signals,
    dampen_urgency_for_trusted_auth,
    effective_reputation_overlay_points,
    reputation_notice_text,
    sender_breakdown_points,
    weighted_non_urgency_and_urgency,
)
from app.scoring.auth_band import AuthBand, auth_band
from app.scoring.combos.context import ScoringContext, build_scoring_context
from app.scoring.combos.evaluator import ComboResult, evaluate_combos
from app.scoring.legitimacy import LegitimacyContext, cap_transactional_content, compute_legitimacy
from app.scoring.signals.attachments import evaluate_attachments
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals.content import evaluate_urgency
from app.scoring.signals.headers import evaluate_headers
from app.scoring.signals.sender import evaluate_sender
from app.scoring.signals.urls import evaluate_urls
from app.scoring.types import Finding, SignalChunk


class ScoringPipeline:
    """Orchestrates reputation, signal chunks, combos, caps, and response assembly."""

    def score(self, req: ScoreRequest) -> ScoreResponse:
        rep = self._run_reputation(req)
        brand_chunk, brand_findings = evaluate_brand_impersonation(req)
        auth = auth_band(req)
        legitimacy = compute_legitimacy(req, auth, brand_chunk, brand_findings)
        reputation_softened = self._reputation_softened(rep, legitimacy)

        chunks = self._build_chunks(req, brand_chunk, legitimacy, rep)
        chunks["urgency"], urgency_dampened = dampen_urgency_for_trusted_auth(chunks, auth)

        total, combo, reputation_floor, critical_capped = self._apply_combos_and_caps(
            req, chunks, rep, legitimacy, brand_findings=brand_findings
        )

        return self._build_response(
            req,
            chunks,
            rep,
            auth,
            total,
            combo=combo,
            urgency_dampened=urgency_dampened,
            reputation_floor=reputation_floor,
            reputation_softened=reputation_softened,
            critical_capped=critical_capped,
        )

    def _run_reputation(self, req: ScoreRequest) -> ReputationRunResult:
        return run_reputation_checks(req.urls)

    def _reputation_softened(self, rep: ReputationRunResult, legitimacy: LegitimacyContext) -> bool:
        overlay_pts = effective_reputation_overlay_points(rep, legitimacy)
        return (
            legitimacy.tier in ("trusted_transactional", "trusted_workflow")
            and rep.overlay_points > overlay_pts + 1e-6
            and rep.providers.get("safe_browsing") != "threat"
        )

    def _build_chunks(
        self,
        req: ScoreRequest,
        brand_chunk: SignalChunk,
        legitimacy: LegitimacyContext,
        rep: ReputationRunResult,
    ) -> dict[str, SignalChunk]:
        overlay_pts = effective_reputation_overlay_points(rep, legitimacy)
        return {
            "headers": evaluate_headers(req),
            "sender": evaluate_sender(req),
            "brand": brand_chunk,
            "urls": evaluate_urls(req, legitimacy=legitimacy),
            "urgency": cap_transactional_content(evaluate_urgency(req), legitimacy),
            "attachments": evaluate_attachments(req),
            "reputation_overlay": SignalChunk(overlay_pts, rep.reasons),
        }

    def _apply_combos_and_caps(
        self,
        req: ScoreRequest,
        chunks: dict[str, SignalChunk],
        rep: ReputationRunResult,
        legitimacy: LegitimacyContext,
        *,
        brand_findings: tuple[Finding, ...],
    ) -> tuple[float, ComboResult, bool, bool]:
        non_urgency, urgency_weighted = weighted_non_urgency_and_urgency(chunks)
        total = non_urgency + urgency_weighted

        ctx: ScoringContext = build_scoring_context(
            req, chunks, brand_findings=brand_findings, legitimacy=legitimacy
        )
        combo = evaluate_combos(ctx)
        total = min(100.0, total + combo.boost)

        total, reputation_floor = apply_reputation_floor(
            total,
            rep,
            legitimacy=legitimacy,
            chunks=chunks,
        )

        total, critical_capped = apply_critical_cap_for_urgency_isolation(
            total,
            rep=rep,
            chunks=chunks,
        )
        return total, combo, reputation_floor, critical_capped

    def _build_response(
        self,
        req: ScoreRequest,
        chunks: dict[str, SignalChunk],
        rep: ReputationRunResult,
        auth: AuthBand,
        total: float,
        *,
        combo: ComboResult,
        urgency_dampened: bool,
        reputation_floor: bool,
        reputation_softened: bool,
        critical_capped: bool,
    ) -> ScoreResponse:
        score = int(round(min(100.0, total)))
        verdict = verdict_from_score(score)
        technical_reasons = compose_reasons(
            chunks,
            limit=LIMITS.MAX_REASONS,
            auth=auth,
            urgency_dampened=urgency_dampened,
            reputation_floor=reputation_floor,
            reputation_softened=reputation_softened,
            critical_capped=critical_capped,
            combo_reasons=combo.reasons,
        )
        signal_breakdown = SignalBreakdown(
            headers=chunks["headers"].points,
            sender=sender_breakdown_points(chunks),
            urls=chunks["urls"].points,
            urgency=chunks["urgency"].points,
            attachments=chunks["attachments"].points,
            reputation_overlay=chunks["reputation_overlay"].points,
        )
        explanation = build_score_explanation(
            technical_reasons,
            verdict,
            signals=signal_breakdown,
            reputation=ReputationSummary(contributed=rep.contributed, providers=rep.providers),
            reputation_notice=reputation_notice_text(rep.notice_kind),
            authentication=req.authentication,
        )
        confidence = confidence_from_signals(req, chunks, rep, auth)

        return ScoreResponse(
            schema_version=SCHEMA_VERSION,
            score=score,
            verdict=verdict,
            confidence=confidence,
            reasons=explanation.reasons,
            explanation=explanation,
            signals=signal_breakdown,
            reputation=ReputationSummary(contributed=rep.contributed, providers=rep.providers),
            reputation_notice=reputation_notice_text(rep.notice_kind),
        )
