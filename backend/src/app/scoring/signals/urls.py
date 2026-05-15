"""URL structural heuristics."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.schemas import ScoreRequest
from app.scoring.legitimacy import LegitimacyContext, host_is_legitimacy_aligned, url_host_aligned_for_brand
from app.scoring.aggregate import (
    aggregate_url_structural,
    points_from_findings,
    url_high_risk_threshold,
)
from app.scoring.parsing.domains import domain_from_address, domains_equal, registrable_domain
from app.scoring.types import Finding, SignalChunk

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

_LOGIN_PATH = re.compile(
    r"/(?:login|log-?in|sign-?in|verify|secure|account|auth|reset|update)(?:[/?#]|$)",
    re.I,
)

# Known ESP / marketing hosts — shortener + auth pass gets softer treatment in combos.
_ESP_ALLOWLIST = frozenset(
    {
        "mailchimp.com",
        "sendgrid.net",
        "mandrillapp.com",
        "sparkpostmail.com",
        "cmail1.com",
        "list-manage.com",
    },
)


def _host_risk(
    url: str,
    *,
    legitimacy: LegitimacyContext | None = None,
) -> tuple[float, list[Finding]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return 22.0, [
            Finding(
                tag="malformed_url",
                severity="medium",
                reason="URL has no recognizable host.",
            ),
        ]

    findings: list[Finding] = []
    score = 0.0

    try:
        ipaddress.ip_address(host.strip("[]"))
        score = max(score, 48.0)
        findings.append(
            Finding(
                tag="ip_literal_host",
                severity="high",
                reason="URL host is a raw IP address, uncommon for legitimate marketing mail.",
            ),
        )
    except ValueError:
        pass

    if "xn--" in host:
        score = max(score, 22.0)
        findings.append(
            Finding(
                tag="punycode_host",
                severity="medium",
                reason="Hostname uses punycode (IDN), which can hide look-alike domains.",
            ),
        )

    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score = max(score, 26.0)
            findings.append(
                Finding(
                    tag="suspicious_tld",
                    severity="medium",
                    reason=f"Hostname ends with a frequently abused TLD ({tld}).",
                ),
            )
            break

    if host in _SHORTENER_HOSTS or any(host.endswith(f".{s}") for s in _SHORTENER_HOSTS):
        score = max(score, 28.0)
        findings.append(
            Finding(
                tag="url_shortener",
                severity="medium",
                reason="Link uses a public shortener, hiding the final destination.",
            ),
        )

    if (parsed.scheme or "").lower() == "http":
        if not (legitimacy and host and host_is_legitimacy_aligned(host, legitimacy)):
            score = max(score, 14.0)
            findings.append(
                Finding(
                    tag="http_scheme",
                    severity="low",
                    reason="At least one URL uses HTTP instead of HTTPS.",
                ),
            )

    path = parsed.path or ""
    if path.count("@") >= 1:
        score = max(score, 32.0)
        findings.append(
            Finding(
                tag="credential_path_trick",
                severity="high",
                reason="URL path contains '@', sometimes used in credential phishing.",
            ),
        )

    if _LOGIN_PATH.search(path):
        if not (legitimacy and host and host_is_legitimacy_aligned(host, legitimacy)):
            score = max(score, 24.0)
            findings.append(
                Finding(
                    tag="login_like_path",
                    severity="medium",
                    reason="URL path resembles a login or verification endpoint.",
                ),
            )

    if re.search(r"https?://https?://", url, re.I):
        score = max(score, 35.0)
        findings.append(
            Finding(
                tag="nested_url",
                severity="high",
                reason="URL appears to embed a nested http(s) prefix.",
            ),
        )

    return min(100.0, score), findings


def _external_link_findings(
    req: ScoreRequest,
    *,
    legitimacy: LegitimacyContext | None = None,
) -> list[Finding]:
    from_domain = domain_from_address(req.from_email)
    if not from_domain or not req.urls:
        return []

    findings: list[Finding] = []
    external = 0
    for url in req.urls:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        link_reg = registrable_domain(host)
        if not link_reg:
            continue
        if domains_equal(from_domain, link_reg):
            continue
        if legitimacy and host_is_legitimacy_aligned(host, legitimacy):
            continue
        if legitimacy and legitimacy.tier in (
            "trusted_transactional",
            "trusted_workflow",
        ) and (
            url_host_aligned_for_brand(host, req)
            or host_is_legitimacy_aligned(host, legitimacy)
        ):
            continue
        external += 1
        findings.append(
            Finding(
                tag="external_link",
                severity="medium",
                reason=(
                    f"Link host {link_reg!r} is outside the sender domain "
                    f"({registrable_domain(from_domain) or from_domain!r})."
                ),
            ),
        )

    if external >= 2:
        findings.append(
            Finding(
                tag="multiple_external_links",
                severity="medium",
                reason=f"Message contains {external} links to external registrable domains.",
            ),
        )
    return findings


def _collect_url_findings(
    req: ScoreRequest,
    *,
    legitimacy: LegitimacyContext | None = None,
) -> tuple[tuple[Finding, ...], float]:
    if not req.urls:
        return ()

    per_url: list[Finding] = []
    best_score = 0.0
    high_risk_count = 0

    high_risk_threshold = url_high_risk_threshold()
    for url in req.urls:
        pts, url_findings = _host_risk(url, legitimacy=legitimacy)
        if pts >= high_risk_threshold:
            high_risk_count += 1
        if pts > best_score:
            best_score = pts
        per_url.extend(url_findings)

    per_url.extend(_external_link_findings(req, legitimacy=legitimacy))

    if high_risk_count > 1:
        per_url.append(
            Finding(
                tag="multiple_high_risk_urls",
                severity="medium",
                reason=f"Multiple high-risk URLs ({high_risk_count}) increase combined link risk.",
            ),
        )
        best_score = aggregate_url_structural(best_score, high_risk_count)

    return _dedupe_findings(per_url), best_score


def _score_from_findings(findings: tuple[Finding, ...], structural_best: float) -> float:
    return points_from_findings(findings, structural_best=structural_best)


def _dedupe_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        key = f"{f.tag}:{f.reason}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return tuple(out)


def evaluate_urls(
    req: ScoreRequest,
    *,
    legitimacy: LegitimacyContext | None = None,
) -> SignalChunk:
    if not req.urls:
        return SignalChunk(0.0, ())

    findings, structural_best = _collect_url_findings(req, legitimacy=legitimacy)
    points = _score_from_findings(findings, structural_best)
    reasons = tuple(f.reason for f in findings)
    return SignalChunk(points, reasons)


def url_findings(
    req: ScoreRequest,
    *,
    legitimacy: LegitimacyContext | None = None,
) -> tuple[Finding, ...]:
    if not req.urls:
        return ()
    findings, _ = _collect_url_findings(req, legitimacy=legitimacy)
    return findings


def url_tags(req: ScoreRequest) -> frozenset[str]:
    return frozenset(f.tag for f in url_findings(req))
