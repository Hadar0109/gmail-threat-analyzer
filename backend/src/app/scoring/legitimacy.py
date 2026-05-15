"""Legitimacy tier classification.

Responsible for trusted transactional/workflow tiers and content dampening inputs.
Does not call reputation vendors or handle HTTP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from app.schemas import ScoreRequest
from app.scoring.auth_band import AuthBand
from app.scoring.parsing.brands import (
    extract_brand_mentions,
    infer_sender_aligned_brand,
    load_brand_registry,
    sender_domain_authorized,
    url_host_matches_brand,
)
from app.scoring.parsing.domains import domain_from_address, domains_equal, registrable_domain
from app.scoring.parsing.workflow import (
    detect_workflow_context,
    workflow_allowed_link_domains,
)
from app.scoring.signals.content.patterns import scoring_blob
from app.scoring.types import Finding, SignalChunk

LegitimacyTier = Literal[
    "trusted_transactional",
    "trusted_workflow",
    "partial_trust",
    "neutral",
    "hostile",
]

_TRUSTED_URL_DAMPEN_TIERS = frozenset({"trusted_transactional", "trusted_workflow"})

_IDENTITY_HOSTILE_TAGS = frozenset(
    {
        "lookalike_domain",
        "brand_url_mismatch",
        "display_name_brand_mismatch",
        "subdomain_deception",
        "homoglyph_domain",
    },
)

_TRANSACTIONAL_RE = re.compile(
    r"\b(receipt|order\s+confirmation|your\s+purchase|payment\s+received|invoice\s+#|"
    r"thank\s+you\s+for\s+your\s+purchase|subscription|shipped|tracking\s+number)\b",
    re.I,
)

# URL finding tags softened for brand-aligned hosts when tier is trusted_transactional.
_URL_DAMPEN_TAGS_L2 = frozenset(
    {
        "http_scheme",
        "external_link",
        "login_like_path",
        "multiple_external_links",
    },
)


@dataclass(frozen=True, slots=True)
class LegitimacyContext:
    tier: LegitimacyTier
    allowed_link_registrable_domains: frozenset[str]
    transactional: bool


def _sender_registrable(req: ScoreRequest) -> str | None:
    dom = domain_from_address(req.from_email)
    return registrable_domain(dom) if dom else None


def _has_identity_hostile_findings(findings: tuple[Finding, ...]) -> bool:
    return any(f.tag in _IDENTITY_HOSTILE_TAGS and f.severity == "high" for f in findings)


def _authorized_sender_brands(req: ScoreRequest) -> tuple[str, ...]:
    from_domain = domain_from_address(req.from_email)
    if not from_domain:
        return ()
    matched: list[str] = []
    for brand in load_brand_registry():
        if sender_domain_authorized(brand, from_domain):
            matched.append(brand.id)
    return tuple(matched)


def _allowed_link_domains(req: ScoreRequest) -> frozenset[str]:
    allowed: set[str] = set()
    sender_reg = _sender_registrable(req)
    if sender_reg:
        allowed.add(sender_reg)
    blob = scoring_blob(req)
    for brand in extract_brand_mentions(blob):
        for domain in brand.domains:
            reg = registrable_domain(domain) or domain
            allowed.add(reg)
    for brand_id in _authorized_sender_brands(req):
        for brand in load_brand_registry():
            if brand.id == brand_id:
                for domain in brand.domains:
                    reg = registrable_domain(domain) or domain
                    allowed.add(reg)
    return frozenset(allowed)


def _links_mostly_aligned(req: ScoreRequest, allowed: frozenset[str]) -> bool:
    if not req.urls:
        return True
    if not allowed:
        return False
    from urllib.parse import urlparse

    aligned = 0
    for url in req.urls:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        link_reg = registrable_domain(host)
        if not link_reg:
            continue
        if any(domains_equal(link_reg, a) for a in allowed):
            aligned += 1
    return aligned >= max(1, len(req.urls) // 2)


def compute_legitimacy(
    req: ScoreRequest,
    auth: AuthBand,
    brand_chunk: SignalChunk,
    brand_findings: tuple[Finding, ...],
) -> LegitimacyContext:
    allowed = _allowed_link_domains(req)
    blob = scoring_blob(req)
    transactional = bool(_TRANSACTIONAL_RE.search(blob))
    workflow = detect_workflow_context(req)

    if workflow:
        allowed = frozenset(set(allowed) | set(workflow_allowed_link_domains(req)))

    if auth == "any_fail" or _has_identity_hostile_findings(brand_findings) or brand_chunk.points >= 44.0:
        return LegitimacyContext("hostile", allowed, transactional)

    if auth != "all_pass":
        return LegitimacyContext("neutral", allowed, transactional)

    if workflow and not _has_identity_hostile_findings(brand_findings) and brand_chunk.points < 44.0:
        return LegitimacyContext("trusted_workflow", allowed, transactional)

    sender_brands = _authorized_sender_brands(req)
    if not sender_brands and not _sender_registrable(req):
        return LegitimacyContext("partial_trust", allowed, transactional)

    if not sender_brands:
        return LegitimacyContext("partial_trust", allowed, transactional)

    if brand_findings and not _links_mostly_aligned(req, allowed):
        return LegitimacyContext("partial_trust", allowed, transactional)

    if _links_mostly_aligned(req, allowed) and (transactional or sender_brands):
        return LegitimacyContext("trusted_transactional", allowed, transactional)

    return LegitimacyContext("partial_trust", allowed, transactional)


def host_is_legitimacy_aligned(host: str, legitimacy: LegitimacyContext) -> bool:
    if legitimacy.tier not in _TRUSTED_URL_DAMPEN_TIERS:
        return False
    link_reg = registrable_domain(host)
    if not link_reg:
        return False
    return any(domains_equal(link_reg, allowed) for allowed in legitimacy.allowed_link_registrable_domains)


def url_host_aligned_for_brand(host: str, req: ScoreRequest) -> bool:
    """True when host matches sender or a brand mentioned in the message."""
    link_reg = registrable_domain(host)
    if not link_reg:
        return False
    sender_reg = _sender_registrable(req)
    if sender_reg and domains_equal(link_reg, sender_reg):
        return True
    display = (req.display_name or "").strip()
    from_domain = domain_from_address(req.from_email)
    inferred = infer_sender_aligned_brand(display, from_domain) if display else None
    if inferred and url_host_matches_brand(host, inferred):
        return True
    for brand in extract_brand_mentions(scoring_blob(req)):
        if url_host_matches_brand(host, brand):
            return True
    return False


def should_suppress_url_finding(tag: str, host: str, legitimacy: LegitimacyContext) -> bool:
    if legitimacy.tier not in _TRUSTED_URL_DAMPEN_TIERS:
        return False
    if tag not in _URL_DAMPEN_TAGS_L2:
        return False
    return host_is_legitimacy_aligned(host, legitimacy)


def cap_transactional_content(chunk: SignalChunk, legitimacy: LegitimacyContext) -> SignalChunk:
    if legitimacy.tier not in _TRUSTED_URL_DAMPEN_TIERS or not legitimacy.transactional:
        return chunk
    from app.scoring.weights import TRANSACTIONAL_CONTENT_CAP_L2

    if chunk.points <= TRANSACTIONAL_CONTENT_CAP_L2:
        return chunk
    return SignalChunk(TRANSACTIONAL_CONTENT_CAP_L2, chunk.reasons)
