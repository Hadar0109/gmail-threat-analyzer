"""LLM scoring signal — agreement, combo boosts, Critical cap (no HTTP)."""

from __future__ import annotations

from dataclasses import dataclass

from app.llm.types import LlmProviderResult, LlmStructuredAnalysis
from app.reputation.providers import ReputationRunResult
from app.scoring.types import SignalChunk


def _reputation_requires_severity_floor(rep: ReputationRunResult) -> bool:
    if rep.providers.get("safe_browsing") == "threat":
        return True
    if rep.providers.get("virustotal") == "malicious":
        return True
    if rep.overlay_points >= 68.0:
        return True
    return False

W_LLM = 0.12
_COMBO_BOOST_EACH = 8.0
_COMBO_BOOST_MAX = 18.0
_CRITICAL_CAP = 77.0

_URL_CORROB = 15.0
_SENDER_CORROB = 30.0
_ATTACH_CORROB = 14.0
_URGENCY_CORROB = 22.0
_REP_OVERLAY_CORROB = 8.0


@dataclass(frozen=True)
class LlmScoringContribution:
    """Deltas and metadata for the engine post-pass."""

    chunk: SignalChunk
    llm_addon: float
    combo_boosts: float
    apply_critical_cap: bool
    status: str


def _corroboration_strength(
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
) -> float:
    score = 0.0
    if chunks["urls"].points >= _URL_CORROB:
        score += 0.28
    if chunks["sender"].points >= _SENDER_CORROB:
        score += 0.24
    if chunks["attachments"].points >= _ATTACH_CORROB:
        score += 0.20
    if chunks["urgency"].points >= _URGENCY_CORROB:
        score += 0.12
    if chunks["reputation_overlay"].points >= _REP_OVERLAY_CORROB:
        score += 0.16
    if _reputation_requires_severity_floor(rep):
        score = max(score, 0.35)
    return min(1.0, score)


def agreement_factor(
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
) -> float:
    strength = _corroboration_strength(chunks, rep)
    return 0.35 + 0.65 * strength


def _structural_corroboration_weak(chunks: dict[str, SignalChunk]) -> bool:
    return (
        chunks["urls"].points < 18.0
        and chunks["sender"].points < 30.0
        and chunks["attachments"].points < 14.0
        and chunks["urgency"].points < 22.0
    )


def _combo_boosts(
    analysis: LlmStructuredAnalysis,
    chunks: dict[str, SignalChunk],
) -> float:
    cats = set(analysis.categories)
    total = 0.0
    if "credential_theft" in cats and chunks["urls"].points >= _URL_CORROB:
        total += _COMBO_BOOST_EACH
    if "financial_fraud" in cats and chunks["sender"].points >= _SENDER_CORROB:
        total += _COMBO_BOOST_EACH
    if "malware_attachment" in cats and chunks["attachments"].points >= _ATTACH_CORROB:
        total += _COMBO_BOOST_EACH
    return min(_COMBO_BOOST_MAX, total)


def _clamp_for_reputation_safety(
    analysis: LlmStructuredAnalysis,
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
    agreement: float,
    combo: float,
) -> tuple[float, float]:
    """Reduce LLM influence when model says not to override clean reputation + weak local."""
    if analysis.should_not_override_reputation is False:
        agreement *= 0.5
        combo *= 0.5
    if (
        analysis.should_not_override_reputation
        and not _reputation_requires_severity_floor(rep)
        and rep.overlay_points < 8.0
        and _structural_corroboration_weak(chunks)
    ):
        agreement = min(agreement, 0.45)
        combo = min(combo, _COMBO_BOOST_EACH * 0.5)
    return agreement, combo


def evaluate_llm_signal(
    provider_result: LlmProviderResult,
    chunks: dict[str, SignalChunk],
    rep: ReputationRunResult,
) -> LlmScoringContribution:
    """Map provider output to scoring deltas; zero contribution on skip/error."""
    status = provider_result.status
    if provider_result.analysis is None or status != "ok":
        return LlmScoringContribution(
            chunk=SignalChunk(0.0, ()),
            llm_addon=0.0,
            combo_boosts=0.0,
            apply_critical_cap=False,
            status=status,
        )

    analysis = provider_result.analysis
    display_points = min(100.0, analysis.risk_points)
    reasons = tuple(analysis.reasons) if analysis.reasons else ()

    agree = agreement_factor(chunks, rep)
    combo = _combo_boosts(analysis, chunks)
    agree, combo = _clamp_for_reputation_safety(analysis, chunks, rep, agree, combo)

    llm_addon = W_LLM * display_points * agree
    apply_cap = (
        display_points >= 55.0
        and _structural_corroboration_weak(chunks)
        and not _reputation_requires_severity_floor(rep)
    )

    return LlmScoringContribution(
        chunk=SignalChunk(display_points, reasons),
        llm_addon=llm_addon,
        combo_boosts=combo,
        apply_critical_cap=apply_cap,
        status=status,
    )


def apply_llm_critical_cap(total: float, contribution: LlmScoringContribution) -> tuple[float, bool]:
    if not contribution.apply_critical_cap or total < 78.0:
        return total, False
    return min(total, _CRITICAL_CAP), True
