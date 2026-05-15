"""URL sanitizer tests.

Responsible for reputation URL normalization and filtering rules.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

import app.reputation.url_sanitizer as url_sanitizer
from app.limits import LIMITS
from app.reputation.url_sanitizer import sanitize_url_for_reputation


def test_accepts_http_https_case_insensitive() -> None:
    assert sanitize_url_for_reputation("HTTPS://Example.COM/path") == "https://example.com/path"
    assert sanitize_url_for_reputation("http://example.com/") == "http://example.com/"


def test_rejects_non_http_scheme() -> None:
    assert sanitize_url_for_reputation("ftp://files.example/a") is None
    assert sanitize_url_for_reputation("javascript:alert(1)") is None
    assert sanitize_url_for_reputation("file:///etc/passwd") is None


def test_strips_sensitive_query_params_case_insensitive() -> None:
    u = sanitize_url_for_reputation(
        "https://oauth.example/cb?Token=secret&client_id=x&CODE=y&ok=1",
    )
    assert u is not None
    assert "secret" not in u
    assert "Token=" not in u and "token=" not in u
    assert "CODE=" not in u and "code=" not in u
    assert "client_id=x" in u
    assert "ok=1" in u


def test_strips_oauth_tokens() -> None:
    u = sanitize_url_for_reputation(
        "https://idp.example/token?access_token=AT&refresh_token=RT&id_token=IT&session=SE&password=pw&auth=a&x=1",
    )
    assert u is not None
    for bad in ("AT", "RT", "IT", "SE", "pw", "access_token", "refresh_token", "id_token"):
        assert bad not in u
    assert "x=1" in u


def test_strips_userinfo() -> None:
    u = sanitize_url_for_reputation("https://user:pass@host.example/path")
    assert u == "https://host.example/path"


def test_blocks_loopback_and_private_ipv4() -> None:
    assert sanitize_url_for_reputation("http://127.0.0.1/") is None
    assert sanitize_url_for_reputation("http://10.0.0.1/") is None
    assert sanitize_url_for_reputation("http://192.168.0.10/") is None
    assert sanitize_url_for_reputation("http://172.16.0.1/") is None


def test_blocks_metadata_and_link_local_ipv4() -> None:
    assert sanitize_url_for_reputation("http://169.254.169.254/latest/meta-data/") is None


def test_blocks_ipv6_loopback_and_unique_local() -> None:
    assert sanitize_url_for_reputation("http://[::1]/") is None
    assert sanitize_url_for_reputation("http://[fd00::1]/") is None


def test_blocks_localhost_hostnames() -> None:
    assert sanitize_url_for_reputation("http://localhost/") is None
    assert sanitize_url_for_reputation("http://app.localhost/login") is None
    assert sanitize_url_for_reputation("http://device.local/") is None


def test_allows_public_host_and_ip() -> None:
    assert sanitize_url_for_reputation("https://example.com/") is not None
    assert sanitize_url_for_reputation("http://8.8.8.8/") == "http://8.8.8.8/"


def test_drops_fragment() -> None:
    u = sanitize_url_for_reputation("https://example.com/a#frag")
    assert u == "https://example.com/a"
    assert "#" not in u


def test_rejects_overlong_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_sanitizer,
        "LIMITS",
        replace(LIMITS, URL_MAX_LEN=40),
    )
    assert sanitize_url_for_reputation("https://example.com/" + "x" * 80) is None


def test_rejects_overlong_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_sanitizer,
        "LIMITS",
        replace(LIMITS, URL_MAX_LEN=20),
    )
    assert sanitize_url_for_reputation("https://example.com/" + "x" * 30) is None


def test_blocks_ipv6_documentation_prefix() -> None:
    assert sanitize_url_for_reputation("http://[2001:db8::1]/") is None


def test_ipv6_netloc_round_trip() -> None:
    u = sanitize_url_for_reputation("http://[2606:4700:4700::1111]/p?q=1")
    assert u == "http://[2606:4700:4700::1111]/p?q=1"


def test_ipv6_with_port() -> None:
    u = sanitize_url_for_reputation("http://[2606:4700:4700::1111]:8080/")
    assert u == "http://[2606:4700:4700::1111]:8080/"


def test_reputation_pipeline_caps_url_count() -> None:
    from app.reputation.providers import _dedupe_urls, _reputation_url_candidates

    urls = [f"https://example.com/p{i}" for i in range(20)]
    trimmed = _dedupe_urls(_reputation_url_candidates(urls))
    assert len(trimmed) == LIMITS.REPUTATION_MAX_URLS_TO_CHECK


def test_reputation_pipeline_skips_private_before_cap() -> None:
    from app.reputation.providers import _dedupe_urls, _reputation_url_candidates

    urls = ["http://127.0.0.1/hide"] + [f"https://public.example/x{i}" for i in range(10)]
    trimmed = _dedupe_urls(_reputation_url_candidates(urls))
    assert all("127.0.0.1" not in u for u in trimmed)
    assert len(trimmed) == LIMITS.REPUTATION_MAX_URLS_TO_CHECK
