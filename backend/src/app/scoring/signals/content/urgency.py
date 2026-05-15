"""Urgency and pressure content detector.

Responsible for time-pressure and deadline language patterns in the content family.
Does not set HTTP deadlines or SLA timers.
"""

from __future__ import annotations

import re

from app.schemas import ScoreRequest

from app.scoring.signals.content.patterns import (
    CategoryScore,
    ContentPattern,
    apply_cap,
    match_patterns,
    scoring_blob,
)

CAP = 30.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(re.compile(r"\burgent(ly)?\b", re.I), "Message language stresses urgency."),
    ContentPattern(
        re.compile(r"\b(immediate|instant)\s+action\b", re.I),
        "Demands immediate action.",
    ),
    ContentPattern(re.compile(r"\bclick\s+here\b", re.I), "Uses generic 'click here' phrasing."),
    ContentPattern(
        re.compile(r"\bact\s+now\b|\btime\s+sensitive\b", re.I),
        "Uses time-pressure phrasing.",
        weight=8.0,
    ),
    ContentPattern(
        re.compile(r"\bwithin\s+\d+\s+(hours?|days?)\b", re.I),
        "Sets a short response deadline.",
        weight=8.0,
    ),
    ContentPattern(
        re.compile(r"\b(required|needed)\s+immediately\b", re.I),
        "Demands immediate action on a sensitive request.",
        weight=9.0,
    ),
    ContentPattern(
        re.compile(r"\breset\s+(your\s+)?password\s+immediately\b", re.I),
        "Demands an immediate password reset.",
        weight=10.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
