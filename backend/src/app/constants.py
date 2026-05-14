"""Shared API constants (schema version is negotiated on every request body)."""

SCHEMA_VERSION = "1.1"

# POST /v1/score: lowercase hex HMAC-SHA256 of the raw JSON body (shared with the Apps Script client).
HMAC_SIGNATURE_HEADER = "X-Body-Signature"

# No reputation HTTP lookups were performed (no keys, no URLs, or nothing to do).
REPUTATION_NOTICE_LOCAL_ONLY = (
    "No external reputation lookups ran; score uses local heuristics only."
)

# At least one provider returned successfully and no reputation overlay risk was added.
REPUTATION_NOTICE_CONSULTED_CLEAN = (
    "Reputation providers were consulted for links; no known threats were reported for the checked URLs."
)

# Reputation overlay increased the risk score (Safe Browsing hit and/or strong VirusTotal signals).
REPUTATION_NOTICE_REPUTATION_RISK = (
    "External reputation (Safe Browsing and/or VirusTotal) reported risk signals; those were merged into the score with caps."
)

# Mixed success: at least one provider answered and at least one failed (timeout, HTTP error, rate limit).
REPUTATION_NOTICE_PARTIAL = (
    "Some reputation providers were unavailable or skipped; the score uses whatever reputation data was available plus local heuristics."
)
