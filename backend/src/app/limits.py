"""Payload caps — Phase 1 validation; rate limits land in Phase 4."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PayloadLimits:
    """Upper bounds for untrusted add-on payloads."""

    SCHEMA_VERSION_MAX_LEN: int = 16
    MESSAGE_ID_MAX_LEN: int = 256
    THREAD_ID_MAX_LEN: int = 256
    EMAIL_MAX_LEN: int = 320
    DISPLAY_NAME_MAX_LEN: int = 256
    SUBJECT_MAX_LEN: int = 998
    SNIPPET_MAX_LEN: int = 4_096
    MAX_URL_ITEMS: int = 64
    URL_MAX_LEN: int = 2_048
    MAX_ATTACHMENTS: int = 32
    ATTACHMENT_FILENAME_MAX_LEN: int = 255
    MIME_TYPE_MAX_LEN: int = 128
    MAX_ATTACHMENT_SIZE_BYTES: int = 512 * 1024 * 1024  # metadata cap only
    REASON_MAX_LEN: int = 512
    MAX_REASONS: int = 32
    REPUTATION_MAX_URLS_TO_CHECK: int = 6
    MAX_SCORE_BODY_BYTES: int = 256 * 1024


LIMITS = PayloadLimits()
