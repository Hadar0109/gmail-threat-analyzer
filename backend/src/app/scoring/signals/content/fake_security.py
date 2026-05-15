"""Fake security-alert and account-compromise language."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest

from app.scoring.signals.content._base import (
    CategoryScore,
    ContentPattern,
    apply_cap,
    match_patterns,
    patterns_match,
    scoring_blob,
)

TAG_ID = "fake_security_alert"

CAP = 35.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bsecurity\s+alert\b", re.I),
        "Uses security-alert phrasing.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\bunauthorized\s+(access|activity|transaction)\b", re.I),
        "Claims unauthorized access or activity.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\baccount\s+compromised\b", re.I),
        "Claims the account was compromised.",
        weight=13.0,
    ),
    ContentPattern(
        re.compile(r"\b(account|access)\s+(suspended|locked|disabled)\b", re.I),
        "Claims an account is suspended or locked.",
    ),
    ContentPattern(
        re.compile(r"\bsuspicious\s+(activity|login)\b", re.I),
        "Warns about suspicious activity or login.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\bunusual\s+activity\b", re.I),
        "References unusual account activity.",
        weight=10.0,
    ),
    ContentPattern(
        re.compile(r"\btemporary\s+restrictions?\b", re.I),
        "Mentions temporary account restrictions.",
        weight=8.0,
    ),
)


def tags_fired(req: ScoreRequest) -> frozenset[str]:
    if patterns_match(scoring_blob(req), _PATTERNS):
        return frozenset({TAG_ID})
    return frozenset()


def detect(req: ScoreRequest) -> CategoryScore:
    return apply_cap(match_patterns(scoring_blob(req), _PATTERNS), CAP)
