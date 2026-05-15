"""Banking, payment, and wire-transfer language."""

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

CAP = 40.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bwire\s+transfer\b", re.I),
        "References wire transfers (common in BEC scams).",
    ),
    ContentPattern(re.compile(r"\bACH\b"), "Mentions ACH transfers."),
    ContentPattern(re.compile(r"\bSWIFT\b"), "Mentions SWIFT transfers."),
    ContentPattern(
        re.compile(r"\bbank\s+account\s+(update|change|details)\b", re.I),
        "Requests bank account changes.",
        weight=11.0,
    ),
    ContentPattern(
        re.compile(r"\b(payment|transfer)\s+(details|instructions)\b", re.I),
        "Shares payment or transfer instructions.",
        weight=9.0,
    ),
    ContentPattern(
        re.compile(r"\b(invoice|payment)\s+(due|overdue|required)\b", re.I),
        "Invoice or payment pressure language.",
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
