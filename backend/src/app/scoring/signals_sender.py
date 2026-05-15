"""Sender / identity drift — Phase 2."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest
from app.scoring.features.domains import domain_from_address, domains_equal
from app.scoring.types import SignalChunk


def evaluate_sender(req: ScoreRequest) -> SignalChunk:
    reasons: list[str] = []
    points = 0.0

    from_dom = domain_from_address(req.from_email)
    if req.reply_to:
        reply_dom = domain_from_address(req.reply_to)
        if from_dom and reply_dom and not domains_equal(from_dom, reply_dom):
            points = max(points, 58.0)
            reasons.append(
                f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom}), "
                "which is common in impersonation and BEC-style mail.",
            )

    dn = (req.display_name or "").strip()
    if dn:
        if len(dn) >= 28 and dn.upper() == dn and any(c.isalpha() for c in dn):
            points = max(points, 18.0)
            reasons.append("Display name is an unusually long all-caps string.")

        if re.search(r"\b(ceo|cfo|president|director|manager)\b", dn, re.I):
            points = max(points, 12.0)
            reasons.append("Display name contains a senior-role title often abused in impersonation.")

    return SignalChunk(min(100.0, points), tuple(dict.fromkeys(reasons)))
