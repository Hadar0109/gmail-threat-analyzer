"""LLM provider unit tests — no live Gemini calls."""

from __future__ import annotations

import json

import httpx
import pytest

from app.constants import SCHEMA_VERSION
from app.llm.provider import (
    _env_bool_opt_out,
    _parse_analysis,
    _resolve_api_key,
    build_redacted_payload,
    run_llm_analysis,
)
from app.reputation.guard import (
    llm_cooldown_active,
    record_llm_rate_limit,
    reset_reputation_guard_for_testing,
    try_reserve_llm_analysis_call,
)
from app.schemas import ScoreRequest


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "user@company.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_env_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_ANALYSIS_ENABLED", raising=False)
    assert _env_bool_opt_out("LLM_ANALYSIS_ENABLED") is True


def test_env_disabled_explicit() -> None:
    import os

    old = os.environ.get("LLM_ANALYSIS_ENABLED")
    os.environ["LLM_ANALYSIS_ENABLED"] = "false"
    try:
        assert _env_bool_opt_out("LLM_ANALYSIS_ENABLED") is False
    finally:
        if old is None:
            os.environ.pop("LLM_ANALYSIS_ENABLED", None)
        else:
            os.environ["LLM_ANALYSIS_ENABLED"] = old


def test_api_key_prefers_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "gem-key")
    monkeypatch.setenv("LLM_API_KEY", "generic-key")
    assert _resolve_api_key() == "gem-key"


def test_api_key_falls_back_to_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("LLM_API_KEY", "generic-key")
    assert _resolve_api_key() == "generic-key"


def test_redaction_strips_emails_and_urls_to_domains() -> None:
    payload = build_redacted_payload(
        _req(
            subject="Reset for alice@evil.com",
            snippet="Click https://evil.com/path?token=secret12345678901234567890",
            urls=["https://www.evil.com/login?session=abc"],
        ),
    )
    assert "[REDACTED_EMAIL]" in payload["subject"]
    assert "evil.com" in payload["url_domains"]
    assert "login" not in str(payload["url_domains"])
    assert "https://" not in json.dumps(payload)


def test_run_skipped_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "false")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    out = run_llm_analysis(_req())
    assert out.status == "skipped_disabled"


def test_run_skipped_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    out = run_llm_analysis(_req())
    assert out.status == "skipped_no_api_key"


def test_run_skipped_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("LLM_BUDGET_MAX_CALLS", "0")
    reset_reputation_guard_for_testing()
    out = run_llm_analysis(_req())
    assert out.status == "skipped_budget"


def test_429_triggers_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("LLM_BUDGET_MAX_CALLS", "10")
    reset_reputation_guard_for_testing()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "rate limit"}})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    out = run_llm_analysis(_req(), client=client)
    assert out.status == "error_rate_limited"
    assert llm_cooldown_active()
    out2 = run_llm_analysis(_req(), client=client)
    assert out2.status == "skipped_cooldown"


def test_success_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    reset_reputation_guard_for_testing()

    model_json = json.dumps(
        {
            "risk_points": 72,
            "confidence": 0.85,
            "categories": ["credential_theft"],
            "reasons": ["Message asks to verify account credentials."],
            "should_not_override_reputation": True,
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {"content": {"parts": [{"text": model_json}]}},
                ],
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    out = run_llm_analysis(_req(subject="Verify your password now"), client=client)
    assert out.status == "ok"
    assert out.analysis is not None
    assert out.analysis.risk_points == 72.0


def test_invalid_json_returns_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    reset_reputation_guard_for_testing()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"candidates": [{"content": {"parts": [{"text": "not json"}]}}]},
        )

    transport = httpx.MockTransport(handler)
    out = run_llm_analysis(_req(), client=httpx.Client(transport=transport))
    assert out.status == "error_invalid_json"


def test_parse_analysis_validates() -> None:
    parsed = _parse_analysis(
        '{"risk_points": 50, "confidence": 0.5, "categories": ["urgency"], '
        '"reasons": ["Urgent tone"], "should_not_override_reputation": true}',
    )
    assert parsed is not None
    assert parsed.risk_points == 50.0


def test_budget_reserve(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_BUDGET_MAX_CALLS", "1")
    reset_reputation_guard_for_testing()
    assert try_reserve_llm_analysis_call() is True
    assert try_reserve_llm_analysis_call() is False


def test_record_rate_limit_sets_cooldown() -> None:
    reset_reputation_guard_for_testing()
    record_llm_rate_limit()
    assert llm_cooldown_active()
