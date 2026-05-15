"""Domain normalization and registrable-domain helpers."""

from __future__ import annotations

from app.scoring.parsing.emails import parse_email_address

# Common consumer mail hosts abused for impersonation (not exhaustive).
FREE_MAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "yandex.com",
        "gmx.com",
        "zoho.com",
    },
)

# Multi-label public suffixes handled without an external PSL dependency.
_MULTI_PART_SUFFIXES: tuple[str, ...] = (
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "or.jp",
    "com.br",
    "com.mx",
    "co.nz",
    "co.za",
    "com.sg",
    "com.hk",
    "co.in",
    "com.tr",
    "com.ar",
)


def normalize_hostname(host: str) -> str:
    return host.strip().lower().rstrip(".")


def domain_from_address(addr: str | None) -> str | None:
    """Return the domain part of an email header value, or None."""
    parsed = parse_email_address(addr)
    return parsed.domain if parsed else None


def registrable_domain(host: str | None) -> str | None:
    """
    Best-effort eTLD+1 (registrable domain) for a hostname.

    Uses a small built-in public-suffix list; sufficient for fixture tests and
  early brand/URL comparisons before optional ``tldextract`` integration.
    """
    if not host:
        return None
    host = normalize_hostname(host)
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        return host

    for suffix in _MULTI_PART_SUFFIXES:
        if host == suffix or host.endswith(f".{suffix}"):
            body = host[: -len(suffix)].rstrip(".")
            if not body:
                return host
            label = body.rsplit(".", 1)[-1]
            return f"{label}.{suffix}"

    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def is_free_mail_domain(domain: str | None) -> bool:
    if not domain:
        return False
    host = normalize_hostname(domain)
    if host in FREE_MAIL_DOMAINS:
        return True
    registrable = registrable_domain(host)
    return registrable in FREE_MAIL_DOMAINS if registrable else False


def domains_equal(left: str | None, right: str | None) -> bool:
    """True when both addresses resolve to the same registrable domain."""
    if not left or not right:
        return False
    left_reg = registrable_domain(normalize_hostname(left))
    right_reg = registrable_domain(normalize_hostname(right))
    return bool(left_reg and right_reg and left_reg == right_reg)
