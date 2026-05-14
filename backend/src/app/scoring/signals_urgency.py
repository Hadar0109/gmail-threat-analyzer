"""Lexicon / urgency heuristics — Phase 2."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest
from app.scoring.types import SignalChunk

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\burgent(ly)?\b", re.I), "Message language stresses urgency."),
    (re.compile(r"\bwire\s+transfer\b", re.I), "References wire transfers (common in BEC scams)."),
    (re.compile(r"\b(immediate|instant)\s+action\b", re.I), "Demands immediate action."),
    (re.compile(r"\bverify\s+your\s+(account|identity)\b", re.I), "Asks to verify an account or identity."),
    (re.compile(r"\bclick\s+here\b", re.I), "Uses generic 'click here' phrasing."),
    (re.compile(r"\b(account|access)\s+(suspended|locked|disabled)\b", re.I), "Claims an account is suspended or locked."),
    (re.compile(r"\b(invoice|payment)\s+(due|overdue|required)\b", re.I), "Invoice or payment pressure language."),
    (re.compile(r"\bgift\s+card\b", re.I), "Mentions gift cards (frequent in refund scams)."),
)


def evaluate_urgency(req: ScoreRequest) -> SignalChunk:
    blob = f"{req.subject}\n{req.snippet}".lower()
    hits: list[str] = []
    for pat, reason in _PATTERNS:
        if pat.search(blob):
            hits.append(reason)
    per = 12.0
    points = min(100.0, len(hits) * per)
    return SignalChunk(points, tuple(dict.fromkeys(hits)))
