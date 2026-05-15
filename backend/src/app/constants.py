"""Shared API constants.

Responsible for schema version markers and cross-layer constants (e.g. HMAC header name).
Does not encode scoring weights or detector rules.
"""
SCHEMA_VERSION = "1.2"

# Dual-read window: accept prior client payloads while add-ons roll forward.
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.1", "1.2"})

# POST /score: lowercase hex HMAC-SHA256 of the raw JSON body (shared with the Apps Script client).
HMAC_SIGNATURE_HEADER = "X-Body-Signature"

# No reputation HTTP lookups were performed (no keys, no URLs, or nothing to do).
REPUTATION_NOTICE_LOCAL_ONLY = (
    "Link safety databases were not checked for this message; the score is based on patterns in the email itself."
)

# At least one provider returned successfully and no reputation overlay risk was added.
REPUTATION_NOTICE_CONSULTED_CLEAN = (
    "Links were checked against safety databases; nothing known was reported for the URLs we could review."
)

# Reputation overlay increased the risk score (Safe Browsing hit and/or strong VirusTotal signals).
REPUTATION_NOTICE_REPUTATION_RISK = (
    "A link in this email matched known unsafe reports from external safety databases."
)

# Mixed success: at least one provider answered and at least one failed (timeout, HTTP error, rate limit).
REPUTATION_NOTICE_PARTIAL = (
    "Some link safety checks could not be completed; the score uses whatever link data was available."
)
