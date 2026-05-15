"""Build scoring context (tags, findings, auth band) for combo evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import ScoreRequest
from app.scoring.auth_band import AuthBand, auth_band
from app.scoring.signals.content._base import scoring_blob
from app.scoring.signals.content import (
    credential,
    crypto_refund,
    delivery,
    fake_security,
    financial,
    invoice,
    otp,
    sensitive,
    social_engineering,
    urgency,
)
from app.scoring.features.domains import domain_from_address
from app.scoring.legitimacy import LegitimacyContext
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals_attachments import attachment_findings
from app.scoring.signals_urls import _SUSPICIOUS_TLDS, url_findings
from app.scoring.types import Finding, SignalChunk

_CONTENT_DETECTORS: tuple[tuple[str, object], ...] = (
    ("credential_request", credential),
    ("financial_request", financial),
    ("invoice_language", invoice),
    ("fake_security_alert", fake_security),
    ("otp_language", otp),
    ("sensitive_data_request", sensitive),
    ("crypto_refund_language", crypto_refund),
    ("delivery_scam_language", delivery),
    ("social_engineering_language", social_engineering),
    ("urgency_language", urgency),
)

_MEDIUM_SEVERITY_TAGS = frozenset(
    {
        "external_link",
        "archive_attachment",
        "brand_mention_foreign_sender",
        "url_shortener",
        "login_like_path",
        "display_name_brand_mismatch",
    },
)


@dataclass(frozen=True, slots=True)
class ScoringContext:
    req: ScoreRequest
    auth: AuthBand
    chunks: dict[str, SignalChunk]
    tags: frozenset[str]
    findings: tuple[Finding, ...]


def _content_tags(req: ScoreRequest) -> frozenset[str]:
    tags: set[str] = set()
    for tag_id, module in _CONTENT_DETECTORS:
        tags_fired = getattr(module, "tags_fired", None)
        if callable(tags_fired) and tags_fired(req):
            tags.add(tag_id)
        elif module.detect(req).points > 0:
            tags.add(tag_id)
    return frozenset(tags)


def _sender_suspicious_tld_tag(req: ScoreRequest) -> frozenset[str]:
    """Sender domain on an frequently abused TLD (combo corroboration only)."""
    dom = domain_from_address(req.from_email)
    if not dom:
        return frozenset()
    low = dom.lower()
    for tld in _SUSPICIOUS_TLDS:
        if low.endswith(tld):
            return frozenset({"suspicious_tld"})
    return frozenset()


def _generic_phishing_tags(req: ScoreRequest) -> frozenset[str]:
    """Low-specificity sender/body cues — combo fuel only, not standalone scoring."""
    tags: set[str] = set()
    blob = scoring_blob(req)
    if re.search(r"\bdear\s+(user|customer|member|account\s+holder)\b", blob, re.I):
        tags.add("generic_greeting")
    display = (req.display_name or "").strip()
    if re.search(r"\bsecurity\s+team\b", display, re.I) or re.search(
        r"\bsecurity\s+team\b",
        blob,
        re.I,
    ):
        tags.add("generic_security_sender")
    return frozenset(tags)


def build_scoring_context(
    req: ScoreRequest,
    chunks: dict[str, SignalChunk],
    *,
    brand_findings: tuple[Finding, ...] | None = None,
    legitimacy: LegitimacyContext | None = None,
) -> ScoringContext:
    auth = auth_band(req)
    _, brand_f = evaluate_brand_impersonation(req) if brand_findings is None else (None, brand_findings)
    all_findings: list[Finding] = [
        *brand_f,
        *url_findings(req, legitimacy=legitimacy),
        *attachment_findings(req),
    ]
    tags: set[str] = set(_content_tags(req))
    tags.update(_generic_phishing_tags(req))
    tags.update(_sender_suspicious_tld_tag(req))
    tags.update(f.tag for f in all_findings)

    if chunks["sender"].points >= 30.0:
        tags.add("suspicious_sender")
    if auth == "any_fail":
        tags.add("auth_fail")
    if auth == "all_pass":
        tags.add("auth_all_pass")

    return ScoringContext(
        req=req,
        auth=auth,
        chunks=chunks,
        tags=frozenset(tags),
        findings=tuple(all_findings),
    )
