"""VirusTotal client.

Responsible for URL report requests and normalizing vendor responses.
Does not merge results into the final score (providers.py does).
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.reputation.guard import record_virustotal_rate_limit

_VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class VirusTotalUrlVerdict:
    status: str
    """skipped_no_api_key | skipped_no_urls | skipped_budget | skipped_cooldown | clean | suspicious
    | malicious | not_found | error_timeout | error_http | error_rate_limited | error_invalid_response"""

    points: float
    latency_ms: int
    detail: str = ""


def _stats_to_points(stats: dict[str, Any]) -> float:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 5:
        return 88.0
    if malicious >= 1:
        return 68.0
    if suspicious >= 10:
        return 42.0
    if suspicious >= 4:
        return 28.0
    if suspicious >= 1:
        return 12.0
    return 0.0


def _label_from_points(points: float) -> str:
    if points >= 68.0:
        return "malicious"
    if points >= 12.0:
        return "suspicious"
    return "clean"


def _parse_vt_url_report(
    r: httpx.Response,
    best_points: float,
) -> tuple[float, bool, str | None]:
    """
    Returns (new_best_points, had_stats_block, error_message).
    error_message is set when the body is unusable; caller should emit error_invalid_response.
    had_stats_block is True when last_analysis_stats was present and a dict.
    """
    try:
        payload = r.json()
    except ValueError:
        return best_points, False, "VirusTotal returned non-JSON or malformed JSON."
    if not isinstance(payload, dict):
        return best_points, False, "VirusTotal JSON root was not an object."
    data = payload.get("data")
    if data is None:
        return best_points, False, None
    if not isinstance(data, dict):
        return best_points, False, "VirusTotal 'data' field had an unexpected type."
    attrs = data.get("attributes")
    if attrs is None:
        return best_points, False, None
    if not isinstance(attrs, dict):
        return best_points, False, "VirusTotal 'attributes' field had an unexpected type."
    stats = attrs.get("last_analysis_stats")
    if stats is None:
        return best_points, False, None
    if not isinstance(stats, dict):
        return best_points, False, "VirusTotal 'last_analysis_stats' had an unexpected type."
    pts = _stats_to_points(stats)
    return max(best_points, pts), True, None


def check_virustotal_urls(
    urls: list[str],
    api_key: str | None,
    *,
    client: httpx.Client,
) -> VirusTotalUrlVerdict:
    if not api_key:
        return VirusTotalUrlVerdict("skipped_no_api_key", 0.0, 0)
    if not urls:
        return VirusTotalUrlVerdict("skipped_no_urls", 0.0, 0)

    best_points = 0.0
    total_ms = 0
    parsed_report = False
    saw_http = False
    last_detail = ""

    for url in urls:
        uid = _url_id(url)
        t0 = time.perf_counter()
        try:
            r = client.get(
                f"{_VT_BASE}/urls/{uid}",
                headers={"x-apikey": api_key},
            )
        except httpx.TimeoutException:
            return VirusTotalUrlVerdict(
                "error_timeout",
                best_points,
                total_ms + int((time.perf_counter() - t0) * 1000),
                detail="VirusTotal request timed out.",
            )
        except httpx.HTTPError as exc:
            return VirusTotalUrlVerdict(
                "error_http",
                best_points,
                total_ms + int((time.perf_counter() - t0) * 1000),
                detail=str(exc),
            )

        elapsed = int((time.perf_counter() - t0) * 1000)
        total_ms += elapsed
        saw_http = True

        if r.status_code == 404:
            continue
        if r.status_code == 429:
            record_virustotal_rate_limit()
            return VirusTotalUrlVerdict(
                "error_rate_limited",
                best_points,
                total_ms,
                detail="HTTP 429",
            )
        if r.status_code != 200:
            last_detail = f"HTTP {r.status_code}"
            continue

        new_best, had_stats, err = _parse_vt_url_report(r, best_points)
        if err is not None:
            return VirusTotalUrlVerdict(
                "error_invalid_response",
                best_points,
                total_ms,
                detail=err,
            )
        best_points = new_best
        if had_stats:
            parsed_report = True

    if not saw_http:
        return VirusTotalUrlVerdict("skipped_no_urls", 0.0, 0)

    if parsed_report:
        return VirusTotalUrlVerdict(_label_from_points(best_points), best_points, total_ms, detail=last_detail)

    if last_detail:
        return VirusTotalUrlVerdict("error_http", 0.0, total_ms, detail=last_detail)

    return VirusTotalUrlVerdict("not_found", 0.0, total_ms)
