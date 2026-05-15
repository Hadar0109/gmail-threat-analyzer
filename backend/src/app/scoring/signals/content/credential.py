"""Credential-theft and account-verification language (gated without corroboration)."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest

from app.scoring.signals.content._base import (
    CategoryScore,
    ContentPattern,
    apply_cap,
    has_content_corroboration,
    match_patterns,
    scoring_blob,
)

CAP_CORROBORATED = 45.0
CAP_ISOLATED = 24.0

_PATTERNS: tuple[ContentPattern, ...] = (
    ContentPattern(
        re.compile(r"\bverify\s+your\s+(account|identity)\b", re.I),
        "Asks to verify an account or identity.",
    ),
    ContentPattern(
        re.compile(r"\b(reset|update)\s+(your\s+)?password\b", re.I),
        "Requests a password reset or update.",
    ),
    ContentPattern(
        re.compile(r"\b(sign\s*in|log\s*in)\s+(again|now|required)\b", re.I),
        "Prompts to sign in again.",
        weight=9.0,
    ),
    ContentPattern(
        re.compile(r"\bsession\s+(expired|timed\s+out)\b", re.I),
        "Claims a session expired.",
        weight=11.0,
    ),
    ContentPattern(
        re.compile(r"\bunusual\s+sign[- ]?in\b", re.I),
        "References unusual sign-in activity.",
        weight=12.0,
    ),
    ContentPattern(
        re.compile(r"\bconfirm\s+your\s+(credentials|login)\b", re.I),
        "Asks to confirm credentials or login.",
        weight=11.0,
    ),
)


def detect(req: ScoreRequest) -> CategoryScore:
    raw = match_patterns(scoring_blob(req), _PATTERNS)
    cap = CAP_CORROBORATED if has_content_corroboration(req) else CAP_ISOLATED
    return apply_cap(raw, cap)
