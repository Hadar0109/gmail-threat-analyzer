"""Scoring weights and thresholds.

Responsible for git-versioned family weights, caps, and tunable scoring constants.
Does not apply weights at runtime beyond being imported by aggregation/combos.
"""
from __future__ import annotations

# Weighted blend families (sum = 1.0). Brand rolls into sender for API breakdown.
FAMILY_WEIGHTS: dict[str, float] = {
    "headers": 0.10,
    "sender": 0.24,
    "urls": 0.22,
    "urgency": 0.16,
    "attachments": 0.12,
    "reputation_overlay": 0.16,
}

# Sender + brand identity merge before applying sender weight.
IDENTITY_BRAND_BLEND_FACTOR = 0.35

# URL: max per link + soft stack for additional high-risk URLs.
URL_HIGH_RISK_POINTS = 24.0
URL_STACK_PER_EXTRA = 6.0
URL_STACK_CAP = 18.0

# Attachments: max + fraction of remaining severities.
ATTACHMENT_SECONDARY_FACTOR = 0.35
ATTACHMENT_HIGH_SEVERITY_MIN = 40.0
ATTACHMENT_HIGH_STACK_FACTOR = 0.72

FINDING_SEVERITY_POINTS: dict[str, float] = {
    "low": 14.0,
    "medium": 24.0,
    "high": 42.0,
}

ATTACHMENT_SEVERITY_POINTS: dict[str, float] = {
    "low": 12.0,
    "medium": 26.0,
    "high": 42.0,
}

# Combo engine additive cap (not a seventh weight).
# Cross-plane archetype combos; corroborated phish should clear the Suspicious band.
COMBO_CONTEXT_BOOST_CAP = 20.0

# Verdict post-adjustments
CRITICAL_SCORE_MIN = 78.0
CRITICAL_CAP_SCORE = 77.0
CRITICAL_CAP_URGENCY_WEIGHTED_MIN = 7.5
CRITICAL_CAP_URL_WEIGHTED_MAX = 4.0
CRITICAL_CAP_IDENTITY_WEIGHTED_MAX = 7.5

REPUTATION_FLOOR_SCORE = 55.0
REPUTATION_OVERLAY_FLOOR_POINTS = 68.0

# Trusted transactional / legitimacy
REPUTATION_OVERLAY_L2_FACTOR = 0.35
REPUTATION_FLOOR_LOCAL_URL_POINTS = 22.0
REPUTATION_FLOOR_LOCAL_IDENTITY_POINTS = 25.0
TRANSACTIONAL_CONTENT_CAP_L2 = 12.0

# Trusted-auth urgency dampening (extends to content family via urgency chunk).
URGENCY_DAMPEN_FACTOR = 0.52
URGENCY_DAMPEN_URL_MAX = 15.0
URGENCY_DAMPEN_IDENTITY_MAX = 22.0
