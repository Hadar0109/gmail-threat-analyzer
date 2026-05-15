"""Sensitive personal or payroll data requests."""

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

CAP = 50.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\b(SSN|social\s+security)\b", re.I),
        "Requests a Social Security number.",
        weight=14.0,
    ),
    ContentPattern(
        re.compile(r"\bW-?2\b"),
        "References tax form W-2.",
        weight=13.0,
    ),
    ContentPattern(
        re.compile(r"\b(passport|driver'?s?\s+license)\b", re.I),
        "Requests government ID details.",
        weight=13.0,
    ),
    ContentPattern(
        re.compile(r"\bpayroll\s+(details|information|records)\b", re.I),
        "Requests payroll information.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\btax\s+(form|document|return)\b", re.I),
        "Requests tax documents.",
        weight=11.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
