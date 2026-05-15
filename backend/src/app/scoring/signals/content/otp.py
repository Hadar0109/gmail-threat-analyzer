"""OTP and login-code content detector.

Responsible for one-time code and login verification language patterns.
Does not authenticate users.
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

TAG_ID = "otp_language"

CAP = 30.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bone[- ]time\s+(code|password|pin)\b", re.I),
        "Requests a one-time code or password.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\bverification\s+code\b", re.I),
        "Mentions a verification code.",
        weight=11.0,
    ),
    ContentPattern(
        re.compile(r"\b\d[\s-]?digit\s+(code|pin)\b", re.I),
        "References a numeric verification code.",
        weight=11.0,
    ),
    ContentPattern(
        re.compile(r"\b(2fa|mfa)\s+(code|token)\b", re.I),
        "Requests a 2FA or MFA code.",
        weight=12.0,
    ),
)


def tags_fired(req: ScoreRequest) -> frozenset[str]:
    if patterns_match(scoring_blob(req), _PATTERNS):
        return frozenset({TAG_ID})
    return frozenset()


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
