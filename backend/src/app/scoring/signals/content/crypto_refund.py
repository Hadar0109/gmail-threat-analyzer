"""Crypto refund scam content detector.

Responsible for cryptocurrency refund and recovery scam language patterns.
Does not interact with blockchains.
"""

from __future__ import annotations

import re

from app.schemas import ScoreRequest

from app.scoring.signals.content.patterns import (
    CategoryScore,
    ContentPattern,
    apply_cap,
    match_patterns,
    patterns_match,
    scoring_blob,
)

TAG_ID = "crypto_refund_language"

CAP = 35.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bgift\s+cards?\b", re.I),
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


def tags_fired(req: ScoreRequest) -> frozenset[str]:
    if patterns_match(scoring_blob(req), _PATTERNS):
        return frozenset({TAG_ID})
    return frozenset()


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
