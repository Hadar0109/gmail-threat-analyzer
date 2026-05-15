"""Brand registry helpers.

Responsible for loading brand data and mention/authorization checks against senders and URLs.
Does not render UI or handle HTTP.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.scoring.parsing.domains import (
    domains_equal,
    is_free_mail_domain,
    normalize_hostname,
    registrable_domain,
)

_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "brands.json"


@dataclass(frozen=True, slots=True)
class BrandEntry:
    id: str
    names: tuple[str, ...]
    domains: frozenset[str]


@lru_cache(maxsize=1)
def load_brand_registry() -> tuple[BrandEntry, ...]:
    raw = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    entries: list[BrandEntry] = []
    for item in raw.get("brands", []):
        domains = frozenset(normalize_hostname(d) for d in item.get("domains", []))
        names = tuple(n.lower().strip() for n in item.get("names", []) if n)
        entries.append(BrandEntry(id=item["id"], names=names, domains=domains))
    return tuple(entries)


def _mention_pattern(name: str) -> re.Pattern[str]:
    escaped = re.escape(name)
    return re.compile(rf"\b{escaped}\b", re.I)


@lru_cache(maxsize=64)
def _compiled_mentions(brand_id: str, names: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(_mention_pattern(n) for n in names)


def extract_brand_mentions(text: str) -> tuple[BrandEntry, ...]:
    """Return brands whose names appear in ``text`` (subject + snippet)."""
    if not text.strip():
        return ()
    hits: list[BrandEntry] = []
    for brand in load_brand_registry():
        patterns = _compiled_mentions(brand.id, brand.names)
        if any(p.search(text) for p in patterns):
            hits.append(brand)
    return tuple(hits)


def sender_domain_authorized(brand: BrandEntry, sender_domain: str | None) -> bool:
    """True when the sender registrable domain matches a brand allowlisted domain."""
    if not sender_domain:
        return False
    sender_reg = registrable_domain(normalize_hostname(sender_domain))
    if not sender_reg:
        return False
    for allowed in brand.domains:
        if domains_equal(sender_reg, allowed) or sender_reg == allowed:
            return True
        allowed_reg = registrable_domain(allowed)
        if allowed_reg and sender_reg == allowed_reg:
            return True
    return False


def display_name_mentions_brand(display_name: str) -> tuple[BrandEntry, ...]:
    return extract_brand_mentions(display_name)


def infer_sender_aligned_brand(
    company_text: str,
    sender_domain: str | None,
) -> BrandEntry | None:
    """
    Build a brand entry when company wording matches the sender registrable domain label.

    Covers retailers and senders not listed in the static registry (e.g. Tradeinn).
    """
    from app.scoring.parsing.emails import parse_email_address
    from app.scoring.parsing.sender_brand_match import (
        company_text_aligns_sender_domain,
        sender_registrable_label,
    )

    host = sender_domain
    if host and "@" in host:
        parsed = parse_email_address(host)
        host = parsed.domain if parsed else host
    if not company_text_aligns_sender_domain(company_text, host):
        return None
    label = sender_registrable_label(host)
    sender_reg = registrable_domain(normalize_hostname(host or ""))
    if not label or not sender_reg:
        return None
    lowered = company_text.strip().lower()
    return BrandEntry(
        id=label,
        names=(lowered, label),
        domains=frozenset({sender_reg}),
    )


def url_host_matches_brand(url_host: str, brand: BrandEntry) -> bool:
    host_reg = registrable_domain(normalize_hostname(url_host))
    if not host_reg:
        return False
    for allowed in brand.domains:
        if domains_equal(host_reg, allowed):
            return True
        allowed_reg = registrable_domain(allowed)
        if allowed_reg and host_reg == allowed_reg:
            return True
    return False


def is_foreign_brand_sender(
    brand: BrandEntry,
    sender_domain: str | None,
    *,
    from_email: str | None = None,
) -> bool:
    """Brand referenced but sender is not aligned with that brand (includes free-mail)."""
    from app.scoring.parsing.sender_brand_match import (
        parsed_from_header,
        sender_aligned_with_brand,
    )

    if not sender_domain:
        return True
    parsed = parsed_from_header(from_email) if from_email else None
    if sender_aligned_with_brand(brand, sender_domain, parsed=parsed):
        return False
    if is_free_mail_domain(sender_domain):
        return True
    return True
