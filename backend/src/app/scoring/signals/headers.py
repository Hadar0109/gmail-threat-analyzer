"""Header signal detector.

Responsible for authentication-result and header anomaly heuristics.
Does not call reputation vendors.
"""
from __future__ import annotations

from app.schemas import MessageAuthentication, ScoreRequest
from app.scoring.types import SignalChunk

_BASELINE_NO_SUMMARY = 6.0
_BASELINE_WITH_SUMMARY = 2.0
_COMPOUND_CAP = 72.0


def _all_fields_absent(auth: MessageAuthentication | None) -> bool:
    if auth is None:
        return True
    return not (auth.spf or auth.dkim or auth.dmarc)


def _mechanism_penalty(label: str, value: str) -> tuple[float, tuple[str, ...]]:
    """Per-mechanism contribution (additive); conservative for unknowns."""
    v = value.strip().lower()
    if v == "pass":
        return 0.0, ()
    if v == "fail":
        return (
            20.0,
            (
                f"{label} result was 'fail' (message did not pass this authentication check).",
            ),
        )
    if v == "softfail":
        return (
            11.0,
            (
                f"{label} reported 'softfail' — the sender is not fully trusted by this mechanism.",
            ),
        )
    if v == "neutral":
        return (
            4.0,
            (
                f"{label} reported 'neutral' (no strong pass or fail signal).",
            ),
        )
    if v == "none":
        return (
            5.0,
            (
                f"{label} reported 'none' (no policy applicable or not evaluated).",
            ),
        )
    if v in {"temperror", "permerror"}:
        return (
            9.0,
            (
                f"{label} reported '{v}' — authentication could not be fully determined.",
            ),
        )
    return (
        9.0,
        (
            f"{label} returned an uncommon or unrecognized result ({value!r}); "
            "treated conservatively.",
        ),
    )


def evaluate_headers(req: ScoreRequest) -> SignalChunk:
    """
    Score SPF / DKIM / DMARC summaries when the add-on supplies them.
    Missing summary keeps a small baseline; failures add capped risk; all-pass lowers baseline.
    """
    auth = req.authentication
    if _all_fields_absent(auth):
        return SignalChunk(
            _BASELINE_NO_SUMMARY,
            (
                "No SPF/DKIM/DMARC summary was provided; header authentication was not scored "
                "beyond a conservative baseline.",
            ),
        )

    if (
        auth.spf
        and auth.dkim
        and auth.dmarc
        and auth.spf.strip().lower() == "pass"
        and auth.dkim.strip().lower() == "pass"
        and auth.dmarc.strip().lower() == "pass"
    ):
        return SignalChunk(
            2.0,
            (
                "SPF, DKIM, and DMARC all reported pass in the summarized authentication results.",
            ),
        )

    points = _BASELINE_WITH_SUMMARY
    reasons: list[str] = []
    for label, raw in (("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)):
        if raw is None or not str(raw).strip():
            continue
        add, rs = _mechanism_penalty(label, str(raw))
        points += add
        reasons.extend(rs)

    points = min(_COMPOUND_CAP, points)
    points = min(100.0, points)

    if not reasons:
        reasons.append(
            "Authentication summary present without explicit failures; "
            "a small residual uncertainty remains.",
        )

    return SignalChunk(points, tuple(dict.fromkeys(reasons)))
