"""Orchestration, budgets, timeouts — Phase 3."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from app.limits import LIMITS
from app.reputation.safebrowsing import SafeBrowsingResult, check_safe_browsing
from app.reputation.url_sanitizer import sanitize_url_for_reputation
from app.reputation.virustotal import VirusTotalUrlVerdict, check_virustotal_urls


@dataclass(frozen=True)
class ReputationRunResult:
    """Aggregated outbound reputation pass for one score request."""

    overlay_points: float
    reasons: tuple[str, ...]
    contributed: bool
    providers: dict[str, str]
    notice_kind: str
    """local_only | consulted_clean | reputation_risk | partial"""


_SKIPPED = frozenset({"skipped_no_api_key", "skipped_no_urls"})


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
        sb = check_safe_browsing(trimmed, sb_key, client=client)
        vt = check_virustotal_urls(trimmed, vt_key, client=client)
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

    return ReputationRunResult(
        overlay_points=overlay,
        reasons=tuple(dict.fromkeys(reasons)),
        contributed=contributed,
        providers=providers,
        notice_kind=notice_kind,
    )
