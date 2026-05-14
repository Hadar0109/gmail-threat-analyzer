"""Sender / identity drift — Phase 2."""

from __future__ import annotations

import re

from app.schemas import ScoreRequest
from app.scoring.types import SignalChunk


def _domain(addr: str) -> str | None:
    addr = addr.strip().lower()
    if "@" not in addr:
        return None
    local, _, host = addr.rpartition("@")
    if not local or not host:
        return None
    return host.strip() or None


def evaluate_sender(req: ScoreRequest) -> SignalChunk:
    reasons: list[str] = []
    points = 0.0

    from_dom = _domain(req.from_email)
    if req.reply_to:
        reply_dom = _domain(req.reply_to)
        if from_dom and reply_dom and reply_dom != from_dom:
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
