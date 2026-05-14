"""Google Safe Browsing v4 client — Phase 3."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.reputation.guard import record_safe_browsing_rate_limit

_SB_FIND_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


@dataclass(frozen=True)
class SafeBrowsingResult:
    status: str
    """skipped_no_api_key | skipped_no_urls | skipped_budget | skipped_cooldown | clean | threat
    | error_timeout | error_http | error_rate_limited | error_invalid_response"""

    threat_match: bool
    latency_ms: int
    detail: str = ""


def _parse_threat_response(raw: httpx.Response, latency_ms: int) -> SafeBrowsingResult:
    try:
        data = raw.json()
    except ValueError:
        return SafeBrowsingResult(
            "error_invalid_response",
            False,
            latency_ms,
            detail="Safe Browsing returned non-JSON or malformed JSON.",
        )
    if not isinstance(data, dict):
        return SafeBrowsingResult(
            "error_invalid_response",
            False,
            latency_ms,
            detail="Safe Browsing JSON root was not an object.",
        )
    matches = data.get("matches")
    if matches is None:
        matches = []
    if not isinstance(matches, list):
        return SafeBrowsingResult(
            "error_invalid_response",
            False,
            latency_ms,
            detail="Safe Browsing 'matches' field had an unexpected type.",
        )
    if not all(isinstance(m, dict) for m in matches):
        return SafeBrowsingResult(
            "error_invalid_response",
            False,
            latency_ms,
            detail="Safe Browsing 'matches' entries had an unexpected shape.",
        )
    if matches:
        return SafeBrowsingResult("threat", True, latency_ms)
    return SafeBrowsingResult("clean", False, latency_ms)


def check_safe_browsing(
    urls: list[str],
    api_key: str | None,
    *,
    client: httpx.Client,
) -> SafeBrowsingResult:
    if not api_key:
        return SafeBrowsingResult("skipped_no_api_key", False, 0)
    if not urls:
        return SafeBrowsingResult("skipped_no_urls", False, 0)

    body: dict[str, Any] = {
        "client": {"clientId": "gmail-malicious-scorer", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    t0 = time.perf_counter()
    try:
        r = client.post(
            _SB_FIND_URL,
            params={"key": api_key},
            json=body,
            headers={"Content-Type": "application/json"},
        )
    except httpx.TimeoutException:
        return SafeBrowsingResult(
            "error_timeout",
            False,
            int((time.perf_counter() - t0) * 1000),
            detail="Safe Browsing request timed out.",
        )
    except httpx.HTTPError as exc:
        return SafeBrowsingResult(
            "error_http",
            False,
            int((time.perf_counter() - t0) * 1000),
            detail=str(exc),
        )

    latency_ms = int((time.perf_counter() - t0) * 1000)
    if r.status_code == 429:
        record_safe_browsing_rate_limit()
        return SafeBrowsingResult(
            "error_rate_limited",
            False,
            latency_ms,
            detail="HTTP 429",
        )
    if r.status_code != 200:
        return SafeBrowsingResult(
            "error_http",
            False,
            latency_ms,
            detail=f"HTTP {r.status_code}",
        )

    return _parse_threat_response(r, latency_ms)
