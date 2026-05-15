"""Email address parsing.

Responsible for normalized addresses and punycode/host extraction helpers.
Does not score messages or call reputation APIs.
"""
from __future__ import annotations

import re
from typing import NamedTuple

# Bare addr-spec or angle-addr inside RFC 5322 display strings.
_ANGLE_ADDR_RE = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")
_BARE_ADDR_RE = re.compile(r"([^\s<>\"]+@[^\s<>\"]+\.[^\s<>\"]+)")
_DOMAIN_LABEL_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
)


class ParsedEmail(NamedTuple):
    """Normalized mailbox parsed from a From/Reply-To header value."""

    local: str
    domain: str
    address: str


def parse_email_address(value: str | None) -> ParsedEmail | None:
    """
    Extract a bare mailbox from common header forms.

    Supports plain ``user@host``, quoted display names with angle brackets,
    and unquoted ``Name user@host`` tails. Returns None when no valid mailbox
    is found.
    """
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None

    candidate = raw
    angle = _ANGLE_ADDR_RE.search(raw)
    if angle:
        candidate = angle.group(1)
    else:
        bare = _BARE_ADDR_RE.search(raw)
        if bare:
            candidate = bare.group(1)
        elif "@" not in raw:
            return None

    candidate = candidate.strip().strip('"').strip("'").lower()
    if "@" not in candidate:
        return None

    local, _, domain = candidate.rpartition("@")
    local = local.strip()
    domain = normalize_domain_part(domain)
    if not local or not domain or " " in local or " " in domain:
        return None
    if not _DOMAIN_LABEL_RE.fullmatch(domain):
        return None

    address = f"{local}@{domain}"
    return ParsedEmail(local=local, domain=domain, address=address)


def normalize_domain_part(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def domain_has_punycode(domain: str) -> bool:
    """True when the domain uses punycode (IDN), including mixed-script risk."""
    return "xn--" in domain.lower()

