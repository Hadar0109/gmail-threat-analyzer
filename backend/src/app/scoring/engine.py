"""Scoring engine entrypoint — Phases 2–3 + Step 6 (weights, verdicts, combination rules)."""

from __future__ import annotations

from typing import Literal

from app.constants import (
    REPUTATION_NOTICE_CONSULTED_CLEAN,
    REPUTATION_NOTICE_LOCAL_ONLY,
    REPUTATION_NOTICE_PARTIAL,
    REPUTATION_NOTICE_REPUTATION_RISK,
    SCHEMA_VERSION,
)
from app.limits import LIMITS
from app.reputation.providers import ReputationRunResult, run_reputation_checks
from app.schemas import (
    ScoreRequest,
    ScoreResponse,
    SignalBreakdown,
    ReputationSummary,
    verdict_from_score,
)
from app.llm.provider import run_llm_analysis
from app.schemas import LlmAnalysisSummary
from app.scoring.signals_attachments import evaluate_attachments
from app.scoring.signals_headers import evaluate_headers
from app.scoring.signals_llm import apply_llm_critical_cap, evaluate_llm_signal
from app.scoring.signals_sender import evaluate_sender
from app.scoring.signals_urgency import evaluate_urgency
from app.scoring.signals_urls import evaluate_urls
from app.scoring.types import SignalChunk

# Weights sum to 1.0 — reputation strengthened vs Step 5 baseline; urgency de-emphasized.
_WEIGHTS: dict[str, float] = {
    "headers": 0.13,
    "sender": 0.21,
    "urls": 0.28,
    "urgency": 0.07,
    "attachments": 0.13,
    "reputation_overlay": 0.18,
}


def _auth_band(req: ScoreRequest) -> Literal["absent", "all_pass", "any_fail", "mixed"]:
    """Summarized SPF/DKIM/DMARC posture when all three fields are present."""
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


def _reputation_requires_severity_floor(rep: ReputationRunResult) -> bool:
    """Strong external hits: at least Dangerous tier after scoring adjustments."""
    if rep.providers.get("safe_browsing") == "threat":
        return True
    if rep.providers.get("virustotal") == "malicious":
        return True
    if rep.overlay_points >= 68.0:
        return True
    return False


def _weighted_non_urgency_and_urgency(chunks: dict[str, SignalChunk]) -> tuple[float, float]:
    nu = 0.0
    for k, w in _WEIGHTS.items():
        if k == "urgency":
            continue
        nu += w * min(100.0, chunks[k].points)
    urg = _WEIGHTS["urgency"] * min(100.0, chunks["urgency"].points)
    return nu, urg


def _dampen_urgency_for_trusted_auth_text_only(
    req: ScoreRequest,
    chunks: dict[str, SignalChunk],
    auth: Literal["absent", "all_pass", "any_fail", "mixed"],
) -> tuple[SignalChunk, bool]:
    """
    When SPF/DKIM/DMARC all pass and there are no strong URL/sender corroborators,
    reduce urgency-only false positives.
    """
    u = chunks["urgency"]
    if auth != "all_pass":
        return u, False
    if chunks["urls"].points >= 15.0 or chunks["sender"].points >= 22.0:
        return u, False
    if u.points <= 0.0:
        return u, False
    before = u.points
    new_pts = min(100.0, u.points * 0.52)
    return SignalChunk(new_pts, u.reasons), new_pts < before - 1e-6


def _reputation_notice_text(notice_kind: str) -> str:
    if notice_kind == "local_only":
        return REPUTATION_NOTICE_LOCAL_ONLY
    if notice_kind == "consulted_clean":
        return REPUTATION_NOTICE_CONSULTED_CLEAN
    if notice_kind == "reputation_risk":
        return REPUTATION_NOTICE_REPUTATION_RISK
    return REPUTATION_NOTICE_PARTIAL


def _confidence_from_signals(
    req: ScoreRequest,
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
    auth: Literal["absent", "all_pass", "any_fail", "mixed"],
) -> float:
    """Higher when more independent channels and/or reputation contribute; lower for urgency-only."""
    c = 0.36
    if req.subject.strip():
        c += 0.06
    if req.snippet.strip():
        c += 0.06
    if req.urls:
        c += 0.08
    if req.attachments:
        c += 0.05
    if req.reply_to:
        c += 0.04
    if "@" in req.from_email:
        c += 0.03
    if auth == "all_pass":
        c += 0.10
    elif auth == "any_fail":
        c += 0.05
    elif auth == "mixed":
        c += 0.03
    if rep.contributed:
        c += 0.08
    corroborators = sum(
        1 for k in ("urls", "sender", "attachments") if chunks[k].points >= 14.0
    )
    if corroborators == 0 and chunks["urgency"].points >= 22.0:
        c -= 0.10
    return round(min(0.95, max(0.32, c)), 4)


def _merge_reasons(chunks: dict[str, SignalChunk], limit: int) -> list[str]:
    ranked: list[tuple[float, str]] = []
    for family, chunk in chunks.items():
        weight = _WEIGHTS.get(family, 0.12 if family == "llm_analysis" else 0.0)
        for r in chunk.reasons:
            ranked.append((chunk.points * weight, r))
    ranked.sort(key=lambda t: t[0], reverse=True)
    out: list[str] = []
    seen: set[str] = set()
    for _, text in ranked:
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    if not out:
        out = [
            "No strong risk patterns matched; score mostly reflects conservative baselines and weak signals.",
            "Review links and sender context manually before taking action.",
        ]
    return out[:limit]


def _compose_reasons(
    chunks: dict[str, SignalChunk],
    *,
    limit: int,
    auth: Literal["absent", "all_pass", "any_fail", "mixed"],
    urgency_dampened: bool,
    auth_sender_boost: bool,
    reputation_floor: bool,
    critical_capped: bool,
    llm_critical_capped: bool = False,
) -> list[str]:
    prefix: list[str] = []
    if auth_sender_boost:
        prefix.append(
            "Authentication failure together with suspicious sender signals increased the combined risk score.",
        )
    if reputation_floor:
        prefix.append(
            "External reputation reported high-severity link signals; overall severity reflects at least elevated danger.",
        )
    if urgency_dampened and auth == "all_pass":
        prefix.append(
            "SPF, DKIM, and DMARC all passed, so urgency-style wording alone was weighted more cautiously.",
        )
    if critical_capped:
        prefix.append(
            "Peak severity was limited because urgency language dominated without enough corroborating link or sender risk.",
        )
    if llm_critical_capped:
        prefix.append(
            "Peak severity was limited because LLM wording concerns lacked enough corroborating link, sender, or attachment risk.",
        )
    merged = _merge_reasons(chunks, max(1, limit - len(prefix)))
    combined = prefix + [r for r in merged if r not in prefix]
    return combined[:limit]


def apply_critical_cap_for_urgency_isolation(
    total: float,
    *,
    rep: ReputationRunResult,
    urgency_points: float,
    url_points: float,
    sender_points: float,
) -> tuple[float, bool]:
    """
    Urgency-heavy, low-corroboration profiles may not reach Critical when
    external reputation did not already demand a severity floor.
    """
    if total < 78.0:
        return total, False
    if _reputation_requires_severity_floor(rep):
        return total, False
    if (
        urgency_points >= 55.0
        and url_points < 18.0
        and sender_points < 30.0
    ):
        return min(total, 77.0), True
    return total, False


def score_message(req: ScoreRequest) -> ScoreResponse:
    """Run local heuristics, optional reputation, combination rules, and verdict mapping."""
    rep = run_reputation_checks(req.urls)

    chunks: dict[str, SignalChunk] = {
        "headers": evaluate_headers(req),
        "sender": evaluate_sender(req),
        "urls": evaluate_urls(req),
        "urgency": evaluate_urgency(req),
        "attachments": evaluate_attachments(req),
        "reputation_overlay": SignalChunk(rep.overlay_points, rep.reasons),
    }

    auth = _auth_band(req)
    chunks["urgency"], urgency_dampened = _dampen_urgency_for_trusted_auth_text_only(req, chunks, auth)

    nu, urg_w = _weighted_non_urgency_and_urgency(chunks)
    total = nu + urg_w

    auth_sender_boost = False
    if auth == "any_fail" and chunks["sender"].points >= 30.0:
        total = min(100.0, total + 12.0)
        auth_sender_boost = True

    reputation_floor = False
    if _reputation_requires_severity_floor(rep) and total < 55.0:
        total = 55.0
        reputation_floor = True

    total, critical_capped = apply_critical_cap_for_urgency_isolation(
        total,
        rep=rep,
        urgency_points=chunks["urgency"].points,
        url_points=chunks["urls"].points,
        sender_points=chunks["sender"].points,
    )

    llm_result = run_llm_analysis(req)
    llm_contrib = evaluate_llm_signal(llm_result, chunks, rep)
    chunks["llm_analysis"] = llm_contrib.chunk
    total = min(100.0, total + llm_contrib.llm_addon + llm_contrib.combo_boosts)
    total, llm_critical_capped = apply_llm_critical_cap(total, llm_contrib)

    score = int(round(min(100.0, total)))
    reasons = _compose_reasons(
        chunks,
        limit=LIMITS.MAX_REASONS,
        auth=auth,
        urgency_dampened=urgency_dampened,
        auth_sender_boost=auth_sender_boost,
        reputation_floor=reputation_floor,
        critical_capped=critical_capped,
        llm_critical_capped=llm_critical_capped,
    )
    confidence = _confidence_from_signals(req, chunks, rep, auth)

    return ScoreResponse(
        schema_version=SCHEMA_VERSION,
        score=score,
        verdict=verdict_from_score(score),
        confidence=confidence,
        reasons=reasons,
        signals=SignalBreakdown(
            headers=chunks["headers"].points,
            sender=chunks["sender"].points,
            urls=chunks["urls"].points,
            urgency=chunks["urgency"].points,
            attachments=chunks["attachments"].points,
            reputation_overlay=chunks["reputation_overlay"].points,
            llm_analysis=chunks["llm_analysis"].points,
        ),
        reputation=ReputationSummary(contributed=rep.contributed, providers=rep.providers),
        reputation_notice=_reputation_notice_text(rep.notice_kind),
        llm_analysis=LlmAnalysisSummary(
            status=llm_contrib.status,
            model=llm_result.model or None,
        ),
    )
