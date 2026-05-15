"""Brand registry and mention extraction for impersonation checks."""

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


def is_foreign_brand_sender(brand: BrandEntry, sender_domain: str | None) -> bool:
    """Brand referenced but sender is not on the brand's domain (includes free-mail)."""
    if not sender_domain:
        return True
    if is_free_mail_domain(sender_domain):
        return True
    return not sender_domain_authorized(brand, sender_domain)
