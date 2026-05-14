"""Normalize and filter URLs before outbound reputation (Safe Browsing / VirusTotal)."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.limits import LIMITS

_STRIP_QUERY_KEYS_LOWER = frozenset(
    {
        "token",
        "code",
        "password",
        "auth",
        "session",
        "access_token",
        "refresh_token",
        "id_token",
    },
)


def _format_netloc(hostname: str, port: int | None) -> str:
    """Rebuild netloc without userinfo; bracket IPv6 literals."""
    is_ipv6 = ":" in hostname
    host_disp = f"[{hostname}]" if is_ipv6 else hostname
    if port is not None:
        return f"{host_disp}:{port}"
    return host_disp


def _host_for_ip_parse(hostname: str) -> str:
    """Strip IPv6 zone id (e.g. fe80::1%eth0) before ip_address()."""
    if "%" in hostname:
        return hostname.split("%", 1)[0]
    return hostname


def _literal_ip_is_blocked(hostname: str) -> bool:
    host = _host_for_ip_parse(hostname)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_unspecified:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved,
    )


def _non_ip_hostname_is_blocked(hostname: str) -> bool:
    h = hostname.casefold()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    if h == "local" or h.endswith(".local"):
        return True
    return False


def _host_is_blocked(hostname: str | None) -> bool:
    if not hostname:
        return True
    if _literal_ip_is_blocked(hostname):
        return True
    try:
        ipaddress.ip_address(_host_for_ip_parse(hostname))
    except ValueError:
        return _non_ip_hostname_is_blocked(hostname)
    return False


def sanitize_url_for_reputation(raw: str) -> str | None:
    """
    Return a safe http(s) URL for reputation lookups, or None if the URL must be skipped.

    - Only http and https schemes (case-insensitive).
    - Strips userinfo (embedded passwords).
    - Removes sensitive query parameter names (case-insensitive).
    - Drops URL fragments.
    - Blocks literal private / reserved / loopback / link-local / multicast IPs and
      obvious local hostnames (localhost, *.localhost, *.local).
    - Enforces LIMITS.URL_MAX_LEN on the serialized result.
    """
    if len(raw) > LIMITS.URL_MAX_LEN:
        return None

    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        return None

    scheme = (parts.scheme or "").casefold()
    if scheme not in {"http", "https"}:
        return None

    hostname = parts.hostname
    if _host_is_blocked(hostname):
        return None

    pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
    filtered = [(k, v) for k, v in pairs if k.casefold() not in _STRIP_QUERY_KEYS_LOWER]
    new_query = urlencode(filtered, doseq=True)

    assert hostname is not None  # guarded by _host_is_blocked
    netloc = _format_netloc(hostname, parts.port)
    path = parts.path or ""

    out = urlunsplit((scheme, netloc, path, new_query, ""))
    if len(out) > LIMITS.URL_MAX_LEN:
        return None
    return out
