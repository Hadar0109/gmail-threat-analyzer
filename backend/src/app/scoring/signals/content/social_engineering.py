"""Authority impersonation, threats, and executive pressure."""

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
        re.compile(r"\b(IRS|internal\s+revenue)\b", re.I),
        "Invokes tax authority (IRS) pressure.",
        weight=13.0,
    ),
    ContentPattern(
        re.compile(r"\b(law\s+enforcement|police|federal\s+agent)\b", re.I),
        "Invokes law-enforcement authority.",
        weight=13.0,
    ),
    ContentPattern(
        re.compile(r"\bCEO\b.*\b(request|approve|transfer)\b", re.I),
        "Uses executive (CEO) pressure for a request.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\b(legal\s+action|arrest\s+warrant|prosecution)\b", re.I),
        "Threatens legal consequences.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\bdo\s+not\s+(tell|share|discuss)\b", re.I),
        "Instructs secrecy (common in BEC).",
        weight=10.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
