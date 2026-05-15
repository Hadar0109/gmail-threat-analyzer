"""HTTP error shaping for POST /score.

Responsible for stable, non-sensitive HTTP error payloads and status mapping.
Does not log requests or verify signatures.
"""
from __future__ import annotations

from fastapi import HTTPException

_SCORE_ERROR_MESSAGES: dict[str, tuple[int, str]] = {
    "hmac_missing": (
        401,
        "Could not verify this request. Try again or contact your administrator.",
    ),
    "hmac_invalid_format": (
        401,
        "Could not verify this request. Try again or contact your administrator.",
    ),
    "hmac_invalid": (
        401,
        "Could not verify this request. Try again or contact your administrator.",
    ),
    "rate_limited": (429, "Too many requests. Please wait and try again."),
    "replay_duplicate": (
        409,
        "This request was already processed. Try again in a few minutes.",
    ),
    "issued_at_invalid": (
        400,
        "The request time is not valid. Reopen the message to try again.",
    ),
    "replay_fields_required": (
        400,
        "The add-on must send fresh request metadata. Update the add-on or try again.",
    ),
    "body_too_large": (413, "The request was too large to process."),
    "empty_body": (400, "The request was empty."),
    "validation_failed": (422, "The request could not be accepted."),
    "service_unavailable": (
        503,
        "Scoring is temporarily unavailable. Please try again later.",
    ),
    "internal_error": (500, "Scoring failed. Please try again later."),
}


def score_public_http_exception(code: str) -> HTTPException:
    if code not in _SCORE_ERROR_MESSAGES:
        code = "internal_error"
    status, message = _SCORE_ERROR_MESSAGES[code]
    return HTTPException(
        status_code=status,
        detail={"code": code, "message": message},
    )
