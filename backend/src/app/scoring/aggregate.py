"""Family rollup, weighted merge, FP guards, and reason composition."""

from __future__ import annotations

from app.constants import (
    REPUTATION_NOTICE_CONSULTED_CLEAN,
    REPUTATION_NOTICE_LOCAL_ONLY,
    REPUTATION_NOTICE_PARTIAL,
    REPUTATION_NOTICE_REPUTATION_RISK,
)
from app.limits import LIMITS
from app.reputation.providers import ReputationRunResult
from app.schemas import ScoreRequest
from app.scoring.weights import (
    ATTACHMENT_HIGH_SEVERITY_MIN,
    ATTACHMENT_HIGH_STACK_FACTOR,
    ATTACHMENT_SECONDARY_FACTOR,
    ATTACHMENT_SEVERITY_POINTS,
    CRITICAL_CAP_IDENTITY_WEIGHTED_MAX,
    CRITICAL_CAP_SCORE,
    CRITICAL_CAP_URGENCY_WEIGHTED_MIN,
    CRITICAL_CAP_URL_WEIGHTED_MAX,
    CRITICAL_SCORE_MIN,
    FAMILY_WEIGHTS,
    FINDING_SEVERITY_POINTS,
    IDENTITY_BRAND_BLEND_FACTOR,
    REPUTATION_FLOOR_LOCAL_IDENTITY_POINTS,
    REPUTATION_FLOOR_LOCAL_URL_POINTS,
    REPUTATION_FLOOR_SCORE,
    REPUTATION_OVERLAY_FLOOR_POINTS,
    REPUTATION_OVERLAY_L2_FACTOR,
    URL_HIGH_RISK_POINTS,
    URL_STACK_CAP,
    URL_STACK_PER_EXTRA,
    URGENCY_DAMPEN_FACTOR,
    URGENCY_DAMPEN_IDENTITY_MAX,
    URGENCY_DAMPEN_URL_MAX,
)
from app.scoring.auth_band import AuthBand
from app.scoring.legitimacy import LegitimacyContext
from app.scoring.types import Finding, SignalChunk


def severity_points(severity: str, table: dict[str, float] | None = None) -> float:
    mapping = table or FINDING_SEVERITY_POINTS
    return mapping.get(severity, 18.0)


def aggregate_max_plus_fraction(
    scores: list[float],
    *,
    secondary_factor: float,
    cap: float = 100.0,
) -> float:
    """Standard policy: best score plus a fraction of the rest (attachments, etc.)."""
    if not scores:
        return 0.0
    ordered = sorted(scores, reverse=True)
    best = ordered[0]
    if len(ordered) == 1:
        return min(cap, best)
    rest = sum(s * secondary_factor for s in ordered[1:])
    return min(cap, best + rest)


def aggregate_attachment_scores(scores: list[float]) -> float:
    """Max + soft stack; high-severity hits stack more aggressively."""
    if not scores:
        return 0.0
    ordered = sorted(scores, reverse=True)
    high = [s for s in ordered if s >= ATTACHMENT_HIGH_SEVERITY_MIN]
    if len(high) >= 2:
        return min(100.0, max(high) + sum(high[1:]) * ATTACHMENT_HIGH_STACK_FACTOR)
    return aggregate_max_plus_fraction(
        ordered,
        secondary_factor=ATTACHMENT_SECONDARY_FACTOR,
    )


def aggregate_url_structural(best_per_url: float, high_risk_count: int) -> float:
    """Max single URL score plus capped soft stack for additional high-risk links."""
    if high_risk_count <= 1:
        return min(100.0, best_per_url)
    stack = min(URL_STACK_CAP, URL_STACK_PER_EXTRA * (high_risk_count - 1))
    return min(100.0, best_per_url + stack)


def points_from_findings(
    findings: tuple[Finding, ...],
    *,
    structural_best: float = 0.0,
    severity_table: dict[str, float] | None = None,
) -> float:
    best = structural_best
    for finding in findings:
        best = max(best, severity_points(finding.severity, severity_table))
    return min(100.0, best)


def points_from_attachment_findings(findings: tuple[Finding, ...]) -> float:
    if not findings:
        return 0.0
    scores = [severity_points(f.severity, ATTACHMENT_SEVERITY_POINTS) for f in findings]
    return aggregate_attachment_scores(scores)


def identity_chunk(chunks: dict[str, SignalChunk]) -> SignalChunk:
    """Blend sender drift and brand impersonation for weighting and dampening gates."""
    sender = chunks["sender"]
    brand = chunks["brand"]
    points = min(
        100.0,
        max(sender.points, brand.points) + min(sender.points, brand.points) * IDENTITY_BRAND_BLEND_FACTOR,
    )
    reasons = tuple(dict.fromkeys((*sender.reasons, *brand.reasons)))
    return SignalChunk(points, reasons)


def weighted_non_urgency_and_urgency(chunks: dict[str, SignalChunk]) -> tuple[float, float]:
    identity = identity_chunk(chunks)
    non_urgency = 0.0
    for key, weight in FAMILY_WEIGHTS.items():
        if key == "urgency":
            continue
        pts = identity.points if key == "sender" else chunks[key].points
        non_urgency += weight * min(100.0, pts)
    urgency_weighted = FAMILY_WEIGHTS["urgency"] * min(100.0, chunks["urgency"].points)
    return non_urgency, urgency_weighted


def dampen_urgency_for_trusted_auth(
    chunks: dict[str, SignalChunk],
    auth: AuthBand,
) -> tuple[SignalChunk, bool]:
    """All-pass auth with weak URL/sender corroborators — reduce content-only false positives."""
    urgency = chunks["urgency"]
    if auth != "all_pass":
        return urgency, False
    identity = identity_chunk(chunks)
    if chunks["urls"].points >= URGENCY_DAMPEN_URL_MAX or identity.points >= URGENCY_DAMPEN_IDENTITY_MAX:
        return urgency, False
    if urgency.points <= 0.0:
        return urgency, False
    before = urgency.points
    new_pts = min(100.0, urgency.points * URGENCY_DAMPEN_FACTOR)
    return SignalChunk(new_pts, urgency.reasons), new_pts < before - 1e-6


def effective_reputation_overlay_points(
    rep: ReputationRunResult,
    legitimacy: LegitimacyContext | None,
) -> float:
    """Dampen VT/SB overlay contribution for trusted transactional mail (not SB threats)."""
    if legitimacy is None or legitimacy.tier not in (
        "trusted_transactional",
        "trusted_workflow",
    ):
        return rep.overlay_points
    if rep.providers.get("safe_browsing") == "threat":
        return rep.overlay_points
    return min(100.0, rep.overlay_points * REPUTATION_OVERLAY_L2_FACTOR)


def reputation_requires_severity_floor(
    rep: ReputationRunResult,
    *,
    legitimacy: LegitimacyContext | None = None,
    chunks: dict[str, SignalChunk] | None = None,
) -> bool:
    if rep.providers.get("safe_browsing") == "threat":
        return True

    vt_hit = rep.providers.get("virustotal") == "malicious" or (
        rep.overlay_points >= REPUTATION_OVERLAY_FLOOR_POINTS
    )
    if not vt_hit:
        return False

    if legitimacy is not None and legitimacy.tier in (
        "trusted_transactional",
        "trusted_workflow",
    ):
        if chunks is None:
            return False
        identity = identity_chunk(chunks)
        local = (
            chunks["urls"].points >= REPUTATION_FLOOR_LOCAL_URL_POINTS
            or identity.points >= REPUTATION_FLOOR_LOCAL_IDENTITY_POINTS
        )
        return local

    return True


def apply_reputation_floor(
    total: float,
    rep: ReputationRunResult,
    *,
    legitimacy: LegitimacyContext | None = None,
    chunks: dict[str, SignalChunk] | None = None,
) -> tuple[float, bool]:
    if reputation_requires_severity_floor(rep, legitimacy=legitimacy, chunks=chunks):
        if total < REPUTATION_FLOOR_SCORE:
            return REPUTATION_FLOOR_SCORE, True
    return total, False


def apply_critical_cap_for_urgency_isolation(
    total: float,
    *,
    rep: ReputationRunResult,
    chunks: dict[str, SignalChunk],
) -> tuple[float, bool]:
    """
    Urgency-heavy, low-corroboration profiles may not reach Critical when
    external reputation did not already demand a severity floor.
    Uses weighted family contributions instead of raw chunk points.
    """
    if total < CRITICAL_SCORE_MIN:
        return total, False
    if reputation_requires_severity_floor(rep, chunks=chunks):
        return total, False

    identity = identity_chunk(chunks)
    urg_w = FAMILY_WEIGHTS["urgency"] * min(100.0, chunks["urgency"].points)
    url_w = FAMILY_WEIGHTS["urls"] * min(100.0, chunks["urls"].points)
    id_w = FAMILY_WEIGHTS["sender"] * min(100.0, identity.points)

    if (
        urg_w >= CRITICAL_CAP_URGENCY_WEIGHTED_MIN
        and url_w < CRITICAL_CAP_URL_WEIGHTED_MAX
        and id_w < CRITICAL_CAP_IDENTITY_WEIGHTED_MAX
    ):
        return min(total, CRITICAL_CAP_SCORE), True
    return total, False


def apply_critical_cap_for_urgency_isolation_legacy(
    total: float,
    *,
    rep: ReputationRunResult,
    urgency_points: float,
    url_points: float,
    sender_points: float,
    brand_points: float = 0.0,
) -> tuple[float, bool]:
    """Backward-compatible wrapper for tests that pass raw family points."""
    combined_identity = max(sender_points, brand_points) + min(
        sender_points,
        brand_points,
    ) * IDENTITY_BRAND_BLEND_FACTOR
    chunks = {
        "urgency": SignalChunk(urgency_points),
        "urls": SignalChunk(url_points),
        "sender": SignalChunk(sender_points),
        "brand": SignalChunk(brand_points),
        "headers": SignalChunk(0.0),
        "attachments": SignalChunk(0.0),
        "reputation_overlay": SignalChunk(0.0),
    }
    return apply_critical_cap_for_urgency_isolation(total, rep=rep, chunks=chunks)


def sender_breakdown_points(chunks: dict[str, SignalChunk]) -> float:
    return identity_chunk(chunks).points


def merge_reasons(
    chunks: dict[str, SignalChunk],
    limit: int,
    *,
    combo_reasons: tuple[str, ...] = (),
) -> list[str]:
    ranked: list[tuple[float, str]] = []
    identity = identity_chunk(chunks)
    for family, chunk in chunks.items():
        if family == "brand":
            continue
        weight = FAMILY_WEIGHTS.get(family, 0.0)
        pts = identity.points if family == "sender" else chunk.points
        for reason in chunk.reasons:
            ranked.append((pts * weight, reason))
    for reason in chunks["brand"].reasons:
        ranked.append((chunks["brand"].points * FAMILY_WEIGHTS["sender"], reason))
    for reason in combo_reasons:
        ranked.append((50.0, reason))
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


def compose_reasons(
    chunks: dict[str, SignalChunk],
    *,
    limit: int,
    auth: AuthBand,
    urgency_dampened: bool,
    reputation_floor: bool,
    reputation_softened: bool,
    critical_capped: bool,
    combo_reasons: tuple[str, ...] = (),
) -> list[str]:
    prefix: list[str] = list(combo_reasons)
    if reputation_softened:
        prefix.append(
            "External reputation flagged a link, but the sender and authentication alignment "
            "were treated as trusted transactional mail so reputation did not force a high severity floor.",
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
    merged = merge_reasons(chunks, max(1, limit - len(prefix)), combo_reasons=())
    combined = prefix + [r for r in merged if r not in prefix]
    return combined[:limit]


def confidence_from_signals(
    req: ScoreRequest,
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
    auth: AuthBand,
) -> float:
    c = 0.36
    if req.subject.strip():
        c += 0.06
    if req.snippet.strip() or (req.body_text_for_scoring or "").strip():
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
    identity = identity_chunk(chunks)
    corroborators = sum(
        1
        for key, pts in (
            ("urls", chunks["urls"].points),
            ("attachments", chunks["attachments"].points),
        )
        if pts >= 14.0
    )
    if identity.points >= 14.0:
        corroborators += 1
    if corroborators == 0 and chunks["urgency"].points >= 22.0:
        c -= 0.10
    return round(min(0.95, max(0.32, c)), 4)


def reputation_notice_text(notice_kind: str) -> str:
    if notice_kind == "local_only":
        return REPUTATION_NOTICE_LOCAL_ONLY
    if notice_kind == "consulted_clean":
        return REPUTATION_NOTICE_CONSULTED_CLEAN
    if notice_kind == "reputation_risk":
        return REPUTATION_NOTICE_REPUTATION_RISK
    return REPUTATION_NOTICE_PARTIAL


def url_high_risk_threshold() -> float:
    return URL_HIGH_RISK_POINTS
