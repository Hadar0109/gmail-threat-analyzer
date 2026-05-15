"""Categorized content-tag scoring (replaces monolithic urgency lexicon)."""

from __future__ import annotations

from collections.abc import Callable

from app.schemas import ScoreRequest
from app.scoring.signals.content import (
    credential,
    crypto_refund,
    delivery,
    fake_security,
    financial,
    invoice,
    otp,
    sensitive,
    social_engineering,
    urgency,
)
from app.scoring.signals.content.patterns import CategoryScore
from app.scoring.types import SignalChunk

_DETECTORS: tuple[Callable[[ScoreRequest], CategoryScore], ...] = (
    urgency.detect,
    credential.detect,
    financial.detect,
    invoice.detect,
    fake_security.detect,
    otp.detect,
    sensitive.detect,
    crypto_refund.detect,
    delivery.detect,
    social_engineering.detect,
)


def evaluate_content(req: ScoreRequest) -> SignalChunk:
    """Aggregate categorized content tags with per-category caps and gating."""
    categories = [detector(req) for detector in _DETECTORS]
    points = min(100.0, sum(c.points for c in categories))
    reasons: list[str] = []
    for category in categories:
        reasons.extend(category.reasons)
    return SignalChunk(points, tuple(dict.fromkeys(reasons)))


def evaluate_urgency(req: ScoreRequest) -> SignalChunk:
    """Backward-compatible alias for the content family (API field: urgency)."""
    return evaluate_content(req)
