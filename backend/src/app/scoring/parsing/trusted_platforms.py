"""Trusted external link platforms (social, ESP, SaaS).

Responsible for hosts that are commonly linked legitimately outside the sender domain.
Does not implement URL scoring or combo rules.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.scoring.parsing.domains import domains_equal, normalize_hostname, registrable_domain

_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "trusted_external_platforms.json"
)


@lru_cache(maxsize=1)
def _platform_hosts() -> frozenset[str]:
    raw = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    return frozenset(
        normalize_hostname(d) for d in raw.get("platform_domains", []) if d
    )


def trusted_external_registrable_domains() -> frozenset[str]:
    out: set[str] = set()
    for host in _platform_hosts():
        reg = registrable_domain(host) or host
        out.add(reg)
    return frozenset(out)


def host_is_trusted_external_platform(host: str) -> bool:
    """True when the link host is a known social, ESP, or common SaaS destination."""
    if not host:
        return False
    host_n = normalize_hostname(host)
    link_reg = registrable_domain(host_n)
    for plat in _platform_hosts():
        plat_n = normalize_hostname(plat)
        plat_reg = registrable_domain(plat_n) or plat_n
        if host_n == plat_n or host_n.endswith(f".{plat_n}"):
            return True
        if link_reg and domains_equal(link_reg, plat_reg):
            return True
    return False
