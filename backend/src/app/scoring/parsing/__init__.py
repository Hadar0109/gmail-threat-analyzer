"""Message parsing package.

Responsible for re-exporting email, domain, brand, and MessageFeatures helpers.
"""

from app.scoring.parsing.domains import (
    FREE_MAIL_DOMAINS,
    domain_from_address,
    domains_equal,
    is_free_mail_domain,
    normalize_hostname,
    registrable_domain,
)
from app.scoring.parsing.brands import (
    BrandEntry,
    extract_brand_mentions,
    load_brand_registry,
    sender_domain_authorized,
)
from app.scoring.parsing.emails import (
    ParsedEmail,
    domain_has_punycode,
    parse_email_address,
)
from app.scoring.parsing.message_features import MessageFeatures
from app.scoring.parsing.homoglyphs import ascii_fold, domains_lookalike, levenshtein

__all__ = [
    "MessageFeatures",
    "BrandEntry",
    "ascii_fold",
    "domains_lookalike",
    "extract_brand_mentions",
    "levenshtein",
    "load_brand_registry",
    "sender_domain_authorized",
    "FREE_MAIL_DOMAINS",
    "ParsedEmail",
    "domain_from_address",
    "domain_has_punycode",
    "domains_equal",
    "is_free_mail_domain",
    "normalize_hostname",
    "parse_email_address",
    "registrable_domain",
]
