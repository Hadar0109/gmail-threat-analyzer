"""SPF/DKIM/DMARC summary band — shared to avoid import cycles."""

from __future__ import annotations

from typing import Literal

from app.schemas import ScoreRequest

AuthBand = Literal["absent", "all_pass", "any_fail", "mixed"]


def auth_band(req: ScoreRequest) -> AuthBand:
    a = req.authentication
    if a is None:
        return "absent"
    parts = (a.spf, a.dkim, a.dmarc)
    if not any(p and str(p).strip() for p in parts):
        return "absent"
    if not all(p and str(p).strip() for p in parts):
        return "mixed"
    vals = [str(p).strip().lower() for p in parts]
    if vals[0] == vals[1] == vals[2] == "pass":
        return "all_pass"
    if any(v == "fail" for v in vals):
        return "any_fail"
    return "mixed"
