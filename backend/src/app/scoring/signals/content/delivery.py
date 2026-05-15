"""Delivery-themed content detector.

Responsible for shipping and delivery notification lure language patterns.
Does not track real parcels.
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
    ContentPattern(
        re.compile(r"\bpackage\s+(held|delayed|detained)\b", re.I),
        "Claims a package is held or delayed.",
        weight=11.0,
    ),
    ContentPattern(
        re.compile(r"\bcustoms\s+(fee|charge|payment)\b", re.I),
        "Requests customs or clearance fees.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\btracking\s+(suspended|failed|issue)\b", re.I),
        "Claims a tracking or delivery problem.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\bdelivery\s+(attempt|failed|notice)\b", re.I),
        "Uses failed-delivery notice phrasing.",
        weight=9.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
