"""URL structural heuristics — Phase 2."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.schemas import ScoreRequest
from app.scoring.types import SignalChunk

_SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "short.link",
    },
)

_SUSPICIOUS_TLDS = frozenset(
    {".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov", ".ru", ".cn", ".top", ".click", ".xyz"},
)


def _host_risk(url: str) -> tuple[float, tuple[str, ...]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return 22.0, ("URL has no recognizable host.",)

    reasons: list[str] = []
    score = 0.0

    try:
        ipaddress.ip_address(host.strip("[]"))
        score = max(score, 48.0)
        reasons.append("URL host is a raw IP address, which is uncommon for legitimate marketing mail.")
    except ValueError:
        pass

    if "xn--" in host:
        score = max(score, 22.0)
        reasons.append("Hostname uses punycode (IDN), which can hide look-alike domains.")

    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score = max(score, 26.0)
            reasons.append(f"Hostname ends with a frequently abused TLD ({tld}).")
            break

    if host in _SHORTENER_HOSTS or any(host.endswith(f".{s}") for s in _SHORTENER_HOSTS):
        score = max(score, 28.0)
        reasons.append("Link uses a public shortener, hiding the final destination from a quick glance.")

    if (parsed.scheme or "").lower() == "http":
        score = max(score, 14.0)
        reasons.append("At least one URL uses HTTP instead of HTTPS.")

    path = parsed.path or ""
    if path.count("@") >= 1:
        score = max(score, 32.0)
        reasons.append("URL path contains '@', sometimes used in credential phishing.")

    if re.search(r"https?://https?://", url, re.I):
        score = max(score, 35.0)
        reasons.append("URL appears to embed a nested http(s) prefix.")

    return min(100.0, score), tuple(dict.fromkeys(reasons))


def evaluate_urls(req: ScoreRequest) -> SignalChunk:
    if not req.urls:
        return SignalChunk(0.0, ())

    best = 0.0
    all_reasons: list[str] = []
    for u in req.urls:
        pts, rs = _host_risk(u)
        if pts > best:
            best = pts
        all_reasons.extend(rs)

    return SignalChunk(best, tuple(dict.fromkeys(all_reasons)))
