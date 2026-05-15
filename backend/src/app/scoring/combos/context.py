"""Build scoring context (tags, findings, auth band) for combo evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.schemas import ScoreRequest
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
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals_attachments import attachment_findings
from app.scoring.signals_urls import url_findings
from app.scoring.types import Finding, SignalChunk

AuthBand = Literal["absent", "all_pass", "any_fail", "mixed"]

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


def auth_band(req: ScoreRequest) -> AuthBand:
    a = req.authentication
    if a is None:
        return "absent"
    parts = (a.spf, a.dkim, a.dmarc)
    if not any(p and str(p).strip() for p in parts):
        return "absent"
    if not all(p and str(p).strip() for p in parts):
        return "mixed"
    vals = [str(p).strip().lower() for p in parts]
    if vals[0] == vals[1] == vals[2] == "pass":
        return "all_pass"
    if any(v == "fail" for v in vals):
        return "any_fail"
    return "mixed"


def _content_tags(req: ScoreRequest) -> frozenset[str]:
    tags: set[str] = set()
    for tag_id, module in _CONTENT_DETECTORS:
        if module.detect(req).points > 0:
            tags.add(tag_id)
    return frozenset(tags)


def build_scoring_context(
    req: ScoreRequest,
    chunks: dict[str, SignalChunk],
    *,
    brand_findings: tuple[Finding, ...] | None = None,
) -> ScoringContext:
    auth = auth_band(req)
    _, brand_f = evaluate_brand_impersonation(req) if brand_findings is None else (None, brand_findings)
    all_findings: list[Finding] = [
        *brand_f,
        *url_findings(req),
        *attachment_findings(req),
    ]
    tags: set[str] = set(_content_tags(req))
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
