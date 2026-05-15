"""Scoring engine entrypoint — public facade over ScoringPipeline."""

from __future__ import annotations

from app.schemas import ScoreRequest, ScoreResponse
from app.scoring.pipeline import ScoringPipeline


def score_message(req: ScoreRequest) -> ScoreResponse:
    """Run local heuristics, optional reputation, combination rules, and verdict mapping."""
    return ScoringPipeline().score(req)
