"""Shared helpers for categorized content-tag detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import ScoreRequest
from app.scoring.parsing.domains import domain_from_address, domains_equal

# Per-pattern weight applied when a regex matches (before category cap).
DEFAULT_TAG_WEIGHT = 10.0


@dataclass(frozen=True, slots=True)
class ContentPattern:
    pattern: re.Pattern[str]
    reason: str
    weight: float = DEFAULT_TAG_WEIGHT


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """Points and reasons from one content category after cap/gating."""

    points: float
    reasons: tuple[str, ...]


def scoring_blob(req: ScoreRequest) -> str:
    body = (req.body_text_for_scoring or req.snippet or "").strip()
    if req.subject and body:
        return f"{req.subject}\n{body}".lower()
    if req.subject:
        return req.subject.lower()
    return body.lower()


def match_patterns(blob: str, patterns: tuple[ContentPattern, ...]) -> CategoryScore:
    reasons: list[str] = []
    points = 0.0
    for entry in patterns:
        if entry.pattern.search(blob):
            reasons.append(entry.reason)
            points += entry.weight
    return CategoryScore(points, tuple(dict.fromkeys(reasons)))


def apply_cap(score: CategoryScore, cap: float) -> CategoryScore:
    if score.points <= cap:
        return score
    return CategoryScore(cap, score.reasons)


def patterns_match(blob: str, patterns: tuple[ContentPattern, ...]) -> bool:
    """True when any pattern matches (used for combo tags independent of points caps)."""
    return any(entry.pattern.search(blob) for entry in patterns)


def has_content_corroboration(req: ScoreRequest) -> bool:
    """
    Second signal for gated categories: risky links, identity drift, or auth failure.
    A bare URL on the same trusted host is not enough.
    """
    if req.urls:
        from app.scoring.signals.urls import url_tags

        if url_tags(req) & frozenset(
            {
                "external_link",
                "login_like_path",
                "ip_literal_host",
                "url_shortener",
                "punycode_host",
                "suspicious_tld",
                "credential_path_trick",
                "nested_url",
            },
        ):
            return True
    if req.authentication:
        parts = (req.authentication.spf, req.authentication.dkim, req.authentication.dmarc)
        if any(p and str(p).strip().lower() == "fail" for p in parts):
            return True
    from_domain = domain_from_address(req.from_email)
    reply_domain = domain_from_address(req.reply_to)
    if from_domain and reply_domain and not domains_equal(from_domain, reply_domain):
        return True
    return False
