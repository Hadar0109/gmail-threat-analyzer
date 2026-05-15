"""Pytest fixtures — isolate tests from developer machine env."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clear_reputation_api_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid accidental live Safe Browsing / VirusTotal calls during the suite."""
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("LLM_ANALYSIS_ENABLED", "false")


@pytest.fixture(autouse=True)
def _clear_hmac_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Most tests run without mandatory HMAC; Phase 4 tests opt in via monkeypatch.setenv."""
    monkeypatch.delenv("HMAC_SECRET", raising=False)
    monkeypatch.delenv("HMAC_SECRET_PREVIOUS", raising=False)


@pytest.fixture(autouse=True)
def _reset_reputation_guard_state() -> None:
    """Isolate in-process reputation budget / cooldown between tests."""
    from app.reputation.guard import reset_reputation_guard_for_testing

    reset_reputation_guard_for_testing()
    yield
    reset_reputation_guard_for_testing()
