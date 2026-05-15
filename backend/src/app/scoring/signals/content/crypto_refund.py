"""Crypto, refund, and gift-card scam language."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest

from app.scoring.signals.content._base import (
    CategoryScore,
    ContentPattern,
    apply_cap,
    match_patterns,
    scoring_blob,
)

CAP = 35.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bgift\s+card\b", re.I),
        "Mentions gift cards (frequent in refund scams).",
    ),
    ContentPattern(
        re.compile(r"\b(bitcoin|btc|crypto\s+wallet|digital\s+wallet)\b", re.I),
        "Mentions cryptocurrency or digital wallets.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\brefund\s+(processing|pending|approval)\b", re.I),
        "Uses refund-processing phrasing.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\bprepaid\s+card\b", re.I),
        "Mentions prepaid cards.",
        weight=10.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
