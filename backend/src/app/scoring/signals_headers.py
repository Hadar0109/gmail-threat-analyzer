"""Header / authentication posture — Phase 2 (conservative when data is missing)."""

from __future__ import annotations

from app.schemas import ScoreRequest
from app.scoring.types import SignalChunk


def evaluate_headers(req: ScoreRequest) -> SignalChunk:
    """
    Without SPF/DKIM/DMARC summaries from the client, treat posture as mildly uncertain.
    Phase 5 can send structured auth results later for stronger signals.
    """
    _ = req
    return SignalChunk(
        8.0,
        (
            "No SPF/DKIM/DMARC summary was provided; header authentication was not scored beyond a conservative baseline.",
        ),
    )
