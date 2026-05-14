"""Scoring engine entrypoint — Phases 2–3."""

from __future__ import annotations

from app.constants import (
    REPUTATION_NOTICE_CONSULTED_CLEAN,
    REPUTATION_NOTICE_LOCAL_ONLY,
    REPUTATION_NOTICE_PARTIAL,
    REPUTATION_NOTICE_REPUTATION_RISK,
    SCHEMA_VERSION,
)
from app.limits import LIMITS
from app.reputation.providers import run_reputation_checks
from app.schemas import (
    ScoreRequest,
    ScoreResponse,
    SignalBreakdown,
    ReputationSummary,
    verdict_from_score,
)
from app.scoring.signals_attachments import evaluate_attachments
from app.scoring.signals_headers import evaluate_headers
from app.scoring.signals_sender import evaluate_sender
from app.scoring.signals_urgency import evaluate_urgency
from app.scoring.signals_urls import evaluate_urls
from app.scoring.types import SignalChunk

_WEIGHTS: dict[str, float] = {
    "headers": 0.15,
    "sender": 0.20,
    "urls": 0.28,
    "urgency": 0.12,
    "attachments": 0.15,
    "reputation_overlay": 0.10,
}


def _reputation_notice_text(notice_kind: str) -> str:
    if notice_kind == "local_only":
        return REPUTATION_NOTICE_LOCAL_ONLY
    if notice_kind == "consulted_clean":
        return REPUTATION_NOTICE_CONSULTED_CLEAN
    if notice_kind == "reputation_risk":
        return REPUTATION_NOTICE_REPUTATION_RISK
    return REPUTATION_NOTICE_PARTIAL


def _confidence_from_coverage(req: ScoreRequest) -> float:
    """Higher when more independent signal channels have usable input."""
    score = 0.42
    if req.subject.strip():
        score += 0.08
    if req.snippet.strip():
        score += 0.10
    if req.urls:
        score += 0.12
    if req.attachments:
        score += 0.06
    if req.reply_to:
        score += 0.07
    if "@" in req.from_email:
        score += 0.05
    return round(min(0.95, score), 4)


def _merge_reasons(chunks: dict[str, SignalChunk], limit: int) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for family, chunk in chunks.items():
        weight = _WEIGHTS.get(family, 0.0)
        for r in chunk.reasons:
            ranked.append((chunk.points * weight, r))
    ranked.sort(key=lambda t: t[0], reverse=True)
    out: list[str] = []
    seen: set[str] = set()
    for _, text in ranked:
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    if not out:
        out = [
            "No strong risk patterns matched; score mostly reflects conservative baselines and weak signals.",
            "Review links and sender context manually before taking action.",
        ]
    return out[:limit]


def score_message(req: ScoreRequest) -> ScoreResponse:
    """Run local heuristics and merge capped reputation overlay (Phase 3)."""
    rep = run_reputation_checks(req.urls)

    chunks = {
        "headers": evaluate_headers(req),
        "sender": evaluate_sender(req),
        "urls": evaluate_urls(req),
        "urgency": evaluate_urgency(req),
        "attachments": evaluate_attachments(req),
        "reputation_overlay": SignalChunk(rep.overlay_points, rep.reasons),
    }

    total = 0.0
    for key, w in _WEIGHTS.items():
        total += w * min(100.0, chunks[key].points)

    score = int(round(min(100.0, total)))
    reasons = _merge_reasons(chunks, LIMITS.MAX_REASONS)

    return ScoreResponse(
        schema_version=SCHEMA_VERSION,
        score=score,
        verdict=verdict_from_score(score),
        confidence=_confidence_from_coverage(req),
        reasons=reasons,
        signals=SignalBreakdown(
            headers=chunks["headers"].points,
            sender=chunks["sender"].points,
            urls=chunks["urls"].points,
            urgency=chunks["urgency"].points,
            attachments=chunks["attachments"].points,
            reputation_overlay=chunks["reputation_overlay"].points,
        ),
        reputation=ReputationSummary(contributed=rep.contributed, providers=rep.providers),
        reputation_notice=_reputation_notice_text(rep.notice_kind),
    )
