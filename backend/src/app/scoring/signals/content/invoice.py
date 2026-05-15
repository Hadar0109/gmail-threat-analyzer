"""Invoice and remittance fraud wording."""

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

CAP = 35.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\binvoice\s+attached\b", re.I),
        "Claims an invoice is attached.",
        weight=11.0,
    ),
    ContentPattern(re.compile(r"\bremittance\b", re.I), "References remittance."),
    ContentPattern(
        re.compile(r"\boverdue\s+(invoice|payment|balance)\b", re.I),
        "States an invoice or payment is overdue.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\bpay\s+this\s+invoice\b", re.I),
        "Directs payment of an invoice.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\boutstanding\s+(invoice|balance)\b", re.I),
        "References an outstanding invoice or balance.",
        weight=9.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
