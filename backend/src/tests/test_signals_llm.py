"""LLM scoring signal tests — mocked provider output."""

from __future__ import annotations

from app.llm.types import LlmProviderResult, LlmStructuredAnalysis
from app.reputation.providers import ReputationRunResult
from app.scoring.signals_llm import (
    agreement_factor,
    apply_llm_critical_cap,
    evaluate_llm_signal,
)
from app.scoring.types import SignalChunk


def _chunks(
    *,
    urls: float = 0.0,
    sender: float = 0.0,
    attachments: float = 0.0,
    urgency: float = 0.0,
    reputation: float = 0.0,
) -> dict[str, SignalChunk]:
    return {
        "headers": SignalChunk(6.0, ()),
        "sender": SignalChunk(sender, ()),
        "urls": SignalChunk(urls, ()),
        "urgency": SignalChunk(urgency, ()),
        "attachments": SignalChunk(attachments, ()),
        "reputation_overlay": SignalChunk(reputation, ()),
    }


def _clean_rep() -> ReputationRunResult:
    return ReputationRunResult(
        overlay_points=0.0,
        reasons=(),
        contributed=False,
        providers={"safe_browsing": "skipped_no_api_key", "virustotal": "skipped_no_api_key"},
        notice_kind="local_only",
    )


def _analysis(**kwargs: object) -> LlmStructuredAnalysis:
    base = {
        "risk_points": 80.0,
        "confidence": 0.9,
        "categories": ["credential_theft"],
        "reasons": ["Asks for password reset."],
        "should_not_override_reputation": True,
    }
    base.update(kwargs)
    return LlmStructuredAnalysis.model_validate(base)


def test_skip_provider_gives_zero_contribution() -> None:
    chunks = _chunks()
    out = evaluate_llm_signal(LlmProviderResult("skipped_no_api_key"), chunks, _clean_rep())
    assert out.llm_addon == 0.0
    assert out.combo_boosts == 0.0
    assert out.chunk.points == 0.0


def test_agreement_lower_without_corroboration() -> None:
    weak = agreement_factor(_chunks(), _clean_rep())
    strong = agreement_factor(_chunks(urls=40.0, sender=50.0), _clean_rep())
    assert strong > weak


def test_combo_boost_credential_theft_and_urls() -> None:
    chunks = _chunks(urls=20.0)
    result = LlmProviderResult(
        "ok",
        analysis=_analysis(categories=["credential_theft"]),
    )
    out = evaluate_llm_signal(result, chunks, _clean_rep())
    assert out.combo_boosts >= 8.0
    assert out.llm_addon > 0.0


def test_llm_only_applies_critical_cap_flag() -> None:
    chunks = _chunks()
    result = LlmProviderResult("ok", analysis=_analysis(risk_points=90.0))
    contrib = evaluate_llm_signal(result, chunks, _clean_rep())
    assert contrib.apply_critical_cap is True
    capped, did = apply_llm_critical_cap(85.0, contrib)
    assert did is True
    assert capped == 77.0


def test_critical_cap_not_when_urls_corroborate() -> None:
    chunks = _chunks(urls=25.0)
    result = LlmProviderResult("ok", analysis=_analysis(risk_points=90.0))
    contrib = evaluate_llm_signal(result, chunks, _clean_rep())
    assert contrib.apply_critical_cap is False


def test_high_llm_with_urls_beats_llm_only_addon() -> None:
    weak_chunks = _chunks()
    strong_chunks = _chunks(urls=20.0)
    result = LlmProviderResult("ok", analysis=_analysis(risk_points=70.0))
    weak = evaluate_llm_signal(result, weak_chunks, _clean_rep())
    strong = evaluate_llm_signal(result, strong_chunks, _clean_rep())
    assert strong.llm_addon + strong.combo_boosts > weak.llm_addon + weak.combo_boosts
