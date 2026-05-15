"""Reputation provider unit tests.

Responsible for provider orchestration, guards, and overlay mapping with mocks.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from app.constants import (
    REPUTATION_NOTICE_REPUTATION_RISK,
    SCHEMA_VERSION,
)
from app.reputation.providers import ReputationRunResult, run_reputation_checks
from app.schemas import ScoreRequest
from app.scoring.engine import score_message


def _mock_transport(sb_json: dict | None = None, vt_json: dict | None = None) -> httpx.MockTransport:
    def dispatch(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "safebrowsing.googleapis.com" in u:
            return httpx.Response(200, json=sb_json or {})
        if "virustotal.com" in u and "/urls/" in u:
            return httpx.Response(200, json=vt_json or {})
        return httpx.Response(404)

    return httpx.MockTransport(dispatch)


def test_run_reputation_local_only_without_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    client = httpx.Client(transport=_mock_transport({}, {}))
    r = run_reputation_checks([], client=client)
    assert r.overlay_points == 0.0
    assert r.notice_kind == "local_only"
    assert r.contributed is False


def test_safe_browsing_threat_drives_overlay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    sb = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    client = httpx.Client(transport=_mock_transport(sb, None))
    r = run_reputation_checks(["http://phishing.example/login"], client=client)
    assert r.overlay_points >= 80.0
    assert r.reasons and "Safe Browsing" in r.reasons[0]
    assert r.notice_kind == "reputation_risk"
    assert r.providers["safe_browsing"] == "threat"
    assert r.providers["virustotal"] == "skipped_no_api_key"


def test_virustotal_malicious_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    vt_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 0,
                    "harmless": 40,
                    "undetected": 10,
                }
            }
        }
    }
    client = httpx.Client(transport=_mock_transport({}, vt_body))
    r = run_reputation_checks(["https://bad.example/a"], client=client)
    assert r.overlay_points >= 68.0
    assert r.notice_kind == "reputation_risk"
    assert r.providers["safe_browsing"] == "skipped_no_api_key"
    assert r.providers["virustotal"] == "malicious"


def test_partial_when_one_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")

    def dispatch(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "safebrowsing.googleapis.com" in u:
            return httpx.Response(500, text="boom")
        if "virustotal.com" in u:
            body = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 6,
                        }
                    }
                }
            }
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://clean.example/"], client=client)
    assert r.notice_kind == "partial"
    assert r.providers["safe_browsing"] == "error_http"


def test_both_providers_clean_consulted_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    vt_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 4,
                }
            }
        }
    }
    client = httpx.Client(transport=_mock_transport({}, vt_body))
    r = run_reputation_checks(["https://trusted.example/"], client=client)
    assert r.overlay_points == 0.0
    assert r.notice_kind == "consulted_clean"
    assert r.contributed is True


def test_safe_browsing_malformed_json_returns_invalid_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "safebrowsing.googleapis.com" in str(request.url):
            return httpx.Response(200, text="not json {")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["http://evil.example/"], client=client)
    assert r.providers["safe_browsing"] == "error_invalid_response"
    assert r.overlay_points == 0.0


def test_safe_browsing_matches_wrong_shape_returns_invalid_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "safebrowsing.googleapis.com" in str(request.url):
            return httpx.Response(200, json={"matches": "not-a-list"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["http://evil.example/"], client=client)
    assert r.providers["safe_browsing"] == "error_invalid_response"


def test_virustotal_malformed_json_returns_invalid_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "virustotal.com" in str(request.url):
            return httpx.Response(200, text="<html>not json</html>")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://bad.example/a"], client=client)
    assert r.providers["virustotal"] == "error_invalid_response"


def test_virustotal_stats_wrong_type_returns_invalid_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    bad = {"data": {"attributes": {"last_analysis_stats": "oops"}}}

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "virustotal.com" in str(request.url):
            return httpx.Response(200, json=bad)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://bad.example/a"], client=client)
    assert r.providers["virustotal"] == "error_invalid_response"


def test_run_reputation_both_skipped_no_api_key_with_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    """No keys: providers skip; no overlay; still a coherent result for the engine."""
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    client = httpx.Client(transport=_mock_transport({}, {}))
    r = run_reputation_checks(["https://example.com/a"], client=client)
    assert r.overlay_points == 0.0
    assert r.providers["safe_browsing"] == "skipped_no_api_key"
    assert r.providers["virustotal"] == "skipped_no_api_key"
    assert r.notice_kind == "local_only"
    assert r.contributed is False


def test_virustotal_429_triggers_cooldown_and_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "virustotal.com" in str(request.url):
            return httpx.Response(429, text="quota")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://quota.example/x"], client=client)
    assert r.providers["virustotal"] == "error_rate_limited"


def test_virustotal_cooldown_skips_second_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """After a VT 429, the next run should not call VirusTotal (cooldown)."""
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    calls = {"vt": 0}

    def dispatch(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "virustotal.com" in u:
            calls["vt"] += 1
            return httpx.Response(429, text="quota")
        return httpx.Response(404)

    transport = httpx.MockTransport(dispatch)
    client = httpx.Client(transport=transport)
    r1 = run_reputation_checks(["https://one.example/a"], client=client)
    assert r1.providers["virustotal"] == "error_rate_limited"
    r2 = run_reputation_checks(["https://two.example/b"], client=client)
    assert r2.providers["virustotal"] == "skipped_cooldown"
    assert calls["vt"] == 1


def test_virustotal_budget_zero_skips_without_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPUTATION_BUDGET_MAX_VT_CALLS", "0")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    calls = {"vt": 0}

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "virustotal.com" in str(request.url):
            calls["vt"] += 1
        return httpx.Response(200, json={})

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://a.example/x", "https://b.example/y"], client=client)
    assert r.providers["virustotal"] == "skipped_budget"
    assert calls["vt"] == 0


def test_virustotal_budget_partial_checks_first_url_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPUTATION_BUDGET_MAX_VT_CALLS", "1")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-vt")
    seen: list[str] = []

    vt_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 0,
                    "harmless": 40,
                    "undetected": 10,
                }
            }
        }
    }

    def dispatch(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "virustotal.com" in u and "/urls/" in u:
            seen.append(u)
            return httpx.Response(200, json=vt_body)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(
        ["https://malicious-first.example/a", "https://benign-second.example/b"],
        client=client,
    )
    assert len(seen) == 1
    assert r.providers["virustotal"] == "malicious"
    assert r.overlay_points >= 68.0


def test_safe_browsing_429_returns_error_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "fake-sb")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")

    def dispatch(request: httpx.Request) -> httpx.Response:
        if "safebrowsing.googleapis.com" in str(request.url):
            return httpx.Response(429, text="quota")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(dispatch))
    r = run_reputation_checks(["https://quota.example/x"], client=client)
    assert r.providers["safe_browsing"] == "error_rate_limited"


def test_score_engine_respects_patched_reputation() -> None:
    with patch("app.scoring.pipeline.run_reputation_checks") as mock_rep:
        mock_rep.return_value = ReputationRunResult(
            overlay_points=84.0,
            reasons=("Google Safe Browsing matched at least one URL against a known threat list.",),
            contributed=True,
            providers={"safe_browsing": "threat", "virustotal": "skipped_no_api_key"},
            notice_kind="reputation_risk",
        )
        out = score_message(
            ScoreRequest.model_validate(
                {
                    "schema_version": SCHEMA_VERSION,
                    "from_email": "a@b.com",
                    "urls": ["http://x.com"],
                },
            ),
        )
    assert out.signals.reputation_overlay == 84.0
    assert out.reputation.contributed is True
    assert out.reputation_notice == REPUTATION_NOTICE_REPUTATION_RISK
