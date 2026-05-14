"""Orchestration, budgets, timeouts — Phase 3."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from app.limits import LIMITS
from app.reputation.guard import (
    safe_browsing_cooldown_active,
    try_reserve_safe_browsing_call,
    try_reserve_virustotal_calls,
    virustotal_cooldown_active,
)
from app.reputation.safebrowsing import SafeBrowsingResult, check_safe_browsing
from app.reputation.url_sanitizer import sanitize_url_for_reputation
from app.reputation.virustotal import VirusTotalUrlVerdict, check_virustotal_urls
from app.score_logging import log_score_event


@dataclass(frozen=True)
class ReputationRunResult:
    """Aggregated outbound reputation pass for one score request."""

    overlay_points: float
    reasons: tuple[str, ...]
    contributed: bool
    providers: dict[str, str]
    notice_kind: str
    """local_only | consulted_clean | reputation_risk | partial"""


def _dedupe_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= LIMITS.REPUTATION_MAX_URLS_TO_CHECK:
            break
    return out


def _reputation_url_candidates(urls: list[str]) -> list[str]:
    """Sanitize then dedupe; caps are enforced in _dedupe_urls."""
    sanitized: list[str] = []
    for u in urls:
        if len(u) > LIMITS.URL_MAX_LEN:
            continue
        s = sanitize_url_for_reputation(u)
        if s is not None:
            sanitized.append(s)
    return sanitized


def _sb_points(res: SafeBrowsingResult) -> float:
    return 84.0 if res.threat_match else 0.0


def _classify_notice(sb: SafeBrowsingResult, vt: VirusTotalUrlVerdict, overlay: float) -> str:
    sb_ok = sb.status in {"clean", "threat"}
    vt_ok = vt.status in {"malicious", "suspicious", "clean", "not_found"}
    sb_err = sb.status.startswith("error")
    vt_err = vt.status.startswith("error")

    contributed = sb_ok or vt_ok
    if not contributed:
        if sb_err or vt_err:
            return "partial"
        return "local_only"

    if overlay >= 8.0:
        return "reputation_risk"
    if sb_err ^ vt_err:
        return "partial"
    return "consulted_clean"


def run_reputation_checks(
    urls: list[str],
    *,
    client: httpx.Client | None = None,
) -> ReputationRunResult:
    """
    Query Safe Browsing (batch) and VirusTotal (per URL, capped) with tight timeouts.
    Providers are skipped when API keys are missing.
    """
    trimmed = _dedupe_urls(_reputation_url_candidates(urls))
    # Env names are documented in backend/.env.example and backend/README.md (must match Render).
    sb_key = (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or "").strip() or None
    vt_key = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip() or None

    close_client = False
    if client is None:
        client = httpx.Client(
            timeout=httpx.Timeout(2.5, connect=2.0),
            follow_redirects=True,
        )
        close_client = True

    try:
        if not sb_key:
            sb = SafeBrowsingResult("skipped_no_api_key", False, 0)
        elif not trimmed:
            sb = SafeBrowsingResult("skipped_no_urls", False, 0)
        elif safe_browsing_cooldown_active():
            log_score_event("reputation_cooldown_skip", provider="safe_browsing")
            sb = SafeBrowsingResult("skipped_cooldown", False, 0)
        elif not try_reserve_safe_browsing_call():
            sb = SafeBrowsingResult("skipped_budget", False, 0)
        else:
            sb = check_safe_browsing(trimmed, sb_key, client=client)

        if not vt_key:
            vt = VirusTotalUrlVerdict("skipped_no_api_key", 0.0, 0)
        elif not trimmed:
            vt = VirusTotalUrlVerdict("skipped_no_urls", 0.0, 0)
        elif virustotal_cooldown_active():
            log_score_event("reputation_cooldown_skip", provider="virustotal")
            vt = VirusTotalUrlVerdict("skipped_cooldown", 0.0, 0)
        else:
            n = try_reserve_virustotal_calls(len(trimmed))
            if n <= 0:
                vt = VirusTotalUrlVerdict("skipped_budget", 0.0, 0)
            else:
                vt_urls = trimmed[:n]
                if n < len(trimmed):
                    log_score_event(
                        "reputation_budget_partial",
                        provider="virustotal",
                        requested=len(trimmed),
                        permitted=n,
                    )
                vt = check_virustotal_urls(vt_urls, vt_key, client=client)
    finally:
        if close_client:
            client.close()

    overlay = min(100.0, max(_sb_points(sb), vt.points))

    reasons: list[str] = []
    if sb.threat_match:
        reasons.append(
            "Google Safe Browsing matched at least one URL against a known threat list.",
        )
    if vt.points >= 68.0:
        reasons.append(
            "VirusTotal reports multiple antivirus engines flagging at least one URL as malicious.",
        )
    elif vt.points >= 28.0:
        reasons.append(
            "VirusTotal shows elevated suspicious verdicts for at least one URL.",
        )
    elif vt.points >= 12.0:
        reasons.append(
            "VirusTotal shows a small number of suspicious verdicts for at least one URL.",
        )

    contributed = sb.status in {"clean", "threat"} or vt.status in {
        "malicious",
        "suspicious",
        "clean",
        "not_found",
    }

    providers = {
        "safe_browsing": sb.status,
        "virustotal": vt.status,
    }

    notice_kind = _classify_notice(sb, vt, overlay)

    log_score_event(
        "reputation_run",
        url_candidates=len(trimmed),
        safe_browsing=sb.status,
        virustotal=vt.status,
        overlay_points=round(overlay, 1),
        contributed=contributed,
        safe_browsing_latency_ms=sb.latency_ms,
        virustotal_latency_ms=vt.latency_ms,
    )
    if sb.status.startswith("error"):
        log_score_event(
            "provider_failure",
            provider="safe_browsing",
            status=sb.status,
            latency_ms=sb.latency_ms,
        )
    if vt.status.startswith("error"):
        log_score_event(
            "provider_failure",
            provider="virustotal",
            status=vt.status,
            latency_ms=vt.latency_ms,
        )

    return ReputationRunResult(
        overlay_points=overlay,
        reasons=tuple(dict.fromkeys(reasons)),
        contributed=contributed,
        providers=providers,
        notice_kind=notice_kind,
    )
