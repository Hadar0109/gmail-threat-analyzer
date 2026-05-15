"""Sender address alignment with detected brands.

Compares brand tokens extracted from message context against all meaningful
parts of the From address (local-part labels, host labels, hyphen/dot segments).
Does not use a hardcoded service-mailbox allowlist.
"""

from __future__ import annotations

import re

from app.scoring.parsing.brands import BrandEntry, sender_domain_authorized
from app.scoring.parsing.domains import normalize_hostname, registrable_domain
from app.scoring.parsing.emails import ParsedEmail, parse_email_address
from app.scoring.parsing.homoglyphs import ascii_fold, domains_lookalike

# Reuse frequently abused TLDs — structural-only alignment is not trusted on these.
_SUSPICIOUS_TLDS = frozenset(
    {".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov", ".ru", ".cn", ".top", ".click", ".xyz"},
)

_TOKEN_SPLIT = re.compile(r"[.\-_+]+")
_MIN_TOKEN_LEN = 4

# Short words in multi-word brand names that are not used alone for matching.
_STOPWORDS = frozenset({"team", "mail", "inc", "llc", "corp"})


def brand_match_tokens(brand: BrandEntry) -> tuple[str, ...]:
    """Distinct normalized tokens (id + names) long enough for structural matching."""
    raw: set[str] = {brand.id.lower().replace(" ", "")}
    for name in brand.names:
        compact = name.lower().replace(" ", "")
        if len(compact) >= _MIN_TOKEN_LEN:
            raw.add(compact)
        for part in _TOKEN_SPLIT.split(name.lower()):
            part = part.strip()
            if len(part) >= _MIN_TOKEN_LEN and part not in _STOPWORDS:
                raw.add(part)
    return tuple(sorted(raw, key=len, reverse=True))


def _hostname_labels(hostname: str) -> tuple[str, ...]:
    host = normalize_hostname(hostname)
    if not host:
        return ()
    return tuple(label for label in host.split(".") if label)


def sender_address_tokens(parsed: ParsedEmail) -> frozenset[str]:
    """All normalized tokens from local-part and full hostname."""
    tokens: set[str] = set()
    for segment in _TOKEN_SPLIT.split(parsed.local):
        folded = ascii_fold(segment)
        if len(folded) >= _MIN_TOKEN_LEN:
            tokens.add(folded)
    for label in _hostname_labels(parsed.domain):
        for segment in _TOKEN_SPLIT.split(label):
            folded = ascii_fold(segment)
            if len(folded) >= _MIN_TOKEN_LEN:
                tokens.add(folded)
    return frozenset(tokens)


def _label_reflects_token(label: str, token: str) -> bool:
    """True when a hostname label naturally embeds the brand token (not a fuzzy spoof)."""
    folded_label = ascii_fold(label)
    folded_token = ascii_fold(token)
    if not folded_token or len(folded_token) < _MIN_TOKEN_LEN:
        return False
    if folded_label == folded_token:
        return True
    # linkedin-security, linkedin.mail, emails-linkedin
    if folded_label.startswith(folded_token + "-") or folded_label.endswith("-" + folded_token):
        return True
    if folded_label.startswith(folded_token + ".") or folded_label.endswith("." + folded_token):
        return True
    return False


def _local_part_reflects_token(local: str, token: str) -> bool:
    folded_token = ascii_fold(token)
    if len(folded_token) < _MIN_TOKEN_LEN:
        return False
    for segment in _TOKEN_SPLIT.split(local):
        if ascii_fold(segment) == folded_token:
            return True
    return False


def _sender_lookalike_brand_domain(hostname: str, brand: BrandEntry) -> bool:
    sender_reg = registrable_domain(hostname)
    for canonical in brand.domains:
        canon_reg = registrable_domain(canonical) or canonical
        if sender_reg and domains_lookalike(sender_reg, canon_reg):
            return True
    for label in _hostname_labels(hostname):
        for segment in _TOKEN_SPLIT.split(label):
            if not segment:
                continue
            for token in brand_match_tokens(brand):
                if domains_lookalike(segment, token):
                    return True
            for canonical in brand.domains:
                canon_reg = registrable_domain(canonical) or canonical
                if domains_lookalike(segment, canon_reg):
                    return True
    return False


def _registrable_on_suspicious_tld(sender_reg: str | None) -> bool:
    if not sender_reg:
        return False
    low = sender_reg.lower()
    return any(low.endswith(tld) for tld in _SUSPICIOUS_TLDS)


def sender_structurally_reflects_brand(parsed: ParsedEmail, brand: BrandEntry) -> bool:
    """
    True when brand tokens appear naturally in the mailbox local-part or host labels.

    Does not grant trust on lookalike registrable domains or abusive TLDs alone.
    """
    sender_reg = registrable_domain(parsed.domain)
    if _registrable_on_suspicious_tld(sender_reg):
        return False
    if _sender_lookalike_brand_domain(parsed.domain, brand):
        return False

    tokens = brand_match_tokens(brand)
    if not tokens:
        return False

    labels = _hostname_labels(parsed.domain)
    for token in tokens:
        if _local_part_reflects_token(parsed.local, token):
            return True
        for label in labels:
            if _label_reflects_token(label, token):
                return True
    return False


def sender_aligned_with_brand(
    brand: BrandEntry,
    sender_domain: str | None,
    *,
    parsed: ParsedEmail | None = None,
) -> bool:
    """
    True when the sender is on an official brand domain or structurally encodes the brand.

    Structural matches require natural token placement and pass anti-spoof checks.
    """
    if sender_domain_authorized(brand, sender_domain):
        return True
    if parsed is None:
        return False
    return sender_structurally_reflects_brand(parsed, brand)


def parsed_from_header(from_email: str | None) -> ParsedEmail | None:
    return parse_email_address(from_email)
