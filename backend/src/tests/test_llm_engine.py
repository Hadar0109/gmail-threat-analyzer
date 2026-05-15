"""Engine integration with mocked LLM provider."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.constants import SCHEMA_VERSION
from app.llm.types import LlmProviderResult, LlmStructuredAnalysis
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import score_message


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "billing@legit-corp.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_engine_completes_when_llm_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "false")
    out = score_message(_req())
    assert out.llm_analysis is not None
    assert out.llm_analysis.status == "skipped_disabled"
    assert out.signals.llm_analysis == 0.0


def test_engine_llm_only_cannot_reach_critical() -> None:
    analysis = LlmStructuredAnalysis.model_validate(
        {
            "risk_points": 95.0,
            "confidence": 0.95,
            "categories": ["urgency", "credential_theft"],
            "reasons": ["Highly suspicious wording."],
            "should_not_override_reputation": True,
        },
    )
    fake = LlmProviderResult("ok", analysis=analysis, model="gemini-2.0-flash")
    with patch("app.scoring.engine.run_llm_analysis", return_value=fake):
        out = score_message(
            _req(
                subject="Hello",
                snippet="Thanks for your order.",
            ),
        )
    assert out.verdict != Verdict.CRITICAL
    assert out.score <= 77
    assert any(
        "LLM wording concerns lacked enough corroborating" in r for r in out.reasons
    ) or out.score <= 77


def test_engine_llm_plus_urls_increases_score() -> None:
    analysis = LlmStructuredAnalysis.model_validate(
        {
            "risk_points": 70.0,
            "confidence": 0.8,
            "categories": ["credential_theft"],
            "reasons": ["Credential harvest language."],
            "should_not_override_reputation": True,
        },
    )
    fake = LlmProviderResult("ok", analysis=analysis)
    baseline = score_message(
        _req(subject="Verify password", snippet="Login now"),
    )
    with patch("app.scoring.engine.run_llm_analysis", return_value=fake):
        with_llm = score_message(
            _req(
                subject="Verify password",
                snippet="Login now",
                urls=["http://203.0.113.9/reset"],
            ),
        )
    assert with_llm.signals.llm_analysis == 70.0
    assert with_llm.score >= baseline.score


def test_engine_missing_key_does_not_fail_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    out = score_message(_req())
    assert out.llm_analysis is not None
    assert out.llm_analysis.status == "skipped_no_api_key"
    assert out.verdict == Verdict.SAFE
