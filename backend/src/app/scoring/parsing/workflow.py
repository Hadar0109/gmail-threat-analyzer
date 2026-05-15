"""Workflow platform matching.

Responsible for interview/scheduling platform signals used in legitimacy and brand checks.
Does not implement combo rules.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from app.schemas import ScoreRequest
from app.scoring.parsing.brands import BrandEntry, extract_brand_mentions, load_brand_registry
from app.scoring.parsing.domains import (
    domain_from_address,
    domains_equal,
    normalize_hostname,
    registrable_domain,
)
from app.scoring.parsing.brands import sender_domain_authorized
from app.scoring.signals.content.patterns import scoring_blob

_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "workflow_platforms.json"

_WORKFLOW_CONTEXT_RE = re.compile(
    r"\b("
    r"interview|invitation|invited|invite|scheduling|schedule(?:d)?|"
    r"calendar|meet(?:ing)?|join\s+(?:the\s+)?(?:call|meeting)|webinar|"
    r"recruiting|recruitment|application|candidate|"
    r"teams\s+meeting|microsoft\s+teams|zoom\s+meeting|google\s+meet|"
    r"comeet|calendly|"
    r"github\s+notification|pull\s+request|issue\s+#\d+|"
    r"receipt|payment\s+received|your\s+order"
    r")\b",
    re.I,
)

_LOGIN_PATH = re.compile(
    r"/(?:login|log-?in|sign-?in|verify|secure|account|auth|reset|update)(?:[/?#]|$)",
    re.I,
)


@lru_cache(maxsize=1)
def _registry() -> tuple[frozenset[str], frozenset[str]]:
    raw = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    domains = frozenset(
        normalize_hostname(d) for d in raw.get("platform_domains", []) if d
    )
    integration = frozenset(str(i).lower() for i in raw.get("integration_brand_ids", []))
    return domains, integration


def integration_brand_ids() -> frozenset[str]:
    return _registry()[1]


def workflow_platform_registrable_domains() -> frozenset[str]:
    out: set[str] = set()
    for host in _registry()[0]:
        reg = registrable_domain(host) or host
        out.add(reg)
    return frozenset(out)


def host_is_workflow_platform(host: str) -> bool:
    """True when the link host is a known recruiting/scheduling/SaaS platform."""
    if not host:
        return False
    host_n = normalize_hostname(host)
    link_reg = registrable_domain(host_n)
    for plat in _registry()[0]:
        plat_n = normalize_hostname(plat)
        plat_reg = registrable_domain(plat_n) or plat_n
        if host_n == plat_n or host_n.endswith(f".{plat_n}"):
            return True
        if link_reg and domains_equal(link_reg, plat_reg):
            return True
    return False


def detect_workflow_context(req: ScoreRequest) -> bool:
    """Scheduling, recruiting, dev notifications, or payment receipts with SaaS links."""
    blob = scoring_blob(req)
    if not _WORKFLOW_CONTEXT_RE.search(blob):
        return False
    if not req.urls:
        return True
    if any(host_is_workflow_platform((urlparse(u).hostname or "")) for u in req.urls):
        return True
    from_dom = domain_from_address(req.from_email)
    sender_reg = registrable_domain(from_dom) if from_dom else None
    if sender_reg and sender_reg in workflow_platform_registrable_domains():
        return True
    if from_dom:
        for brand in load_brand_registry():
            if sender_domain_authorized(brand, from_dom) and brand.id in (
                "paypal",
                "stripe",
                "github",
            ):
                return True
    return False


def impersonation_brand_mentions(req: ScoreRequest) -> tuple[BrandEntry, ...]:
    """Brand names to use for impersonation checks (drops integration brands in workflows)."""
    blob = scoring_blob(req)
    mentioned = extract_brand_mentions(blob)
    if not detect_workflow_context(req):
        return mentioned
    integration = integration_brand_ids()
    return tuple(b for b in mentioned if b.id not in integration)


def company_domains_from_message(req: ScoreRequest) -> frozenset[str]:
    """Registrable domains linked in the message that match company name tokens in the body."""
    blob = scoring_blob(req)
    found: set[str] = set()
    for url in req.urls:
        host = (urlparse(url).hostname or "").lower()
        if not host or host_is_workflow_platform(host):
            continue
        reg = registrable_domain(host)
        if not reg:
            continue
        label = reg.split(".", 1)[0]
        if len(label) >= 4 and re.search(rf"\b{re.escape(label)}\b", blob, re.I):
            found.add(reg)
    return frozenset(found)


def url_could_impersonate_brand(host: str, path: str, brand: BrandEntry) -> bool:
    """True when the URL plausibly targets the brand (not merely co-mentioned in prose)."""
    if url_host_matches_brand(host, brand):
        return False
    if host_is_workflow_platform(host):
        return False
    if _LOGIN_PATH.search(path or ""):
        return True
    compact = host.replace("-", "").replace(".", "").lower()
    for name in brand.names:
        token = name.replace(" ", "").lower()
        if len(token) >= 4 and token in compact:
            return True
    return False


def url_host_matches_brand(url_host: str, brand: BrandEntry) -> bool:
    from app.scoring.parsing.brands import url_host_matches_brand as _match

    return _match(url_host, brand)


def workflow_allowed_link_domains(req: ScoreRequest) -> frozenset[str]:
    allowed: set[str] = set(workflow_platform_registrable_domains())
    allowed.update(company_domains_from_message(req))
    return frozenset(allowed)
