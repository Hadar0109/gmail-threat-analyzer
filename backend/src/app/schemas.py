"""Pydantic request/response models — Phases 1–2."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.constants import SCHEMA_VERSION
from app.limits import LIMITS


class Verdict(StrEnum):
    """Verdict bands from the product README (0–39 / 40–69 / 70–100)."""

    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"


class AttachmentRef(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    filename: str = Field(..., max_length=LIMITS.ATTACHMENT_FILENAME_MAX_LEN)
    mime_type: str = Field(..., max_length=LIMITS.MIME_TYPE_MAX_LEN)
    size_bytes: int | None = Field(
        default=None,
        ge=0,
        le=LIMITS.MAX_ATTACHMENT_SIZE_BYTES,
    )


class MessageAuthentication(BaseModel):
    """Optional SPF/DKIM/DMARC summaries from Authentication-Results (add-on extracted)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    spf: str | None = Field(default=None, max_length=32)
    dkim: str | None = Field(default=None, max_length=32)
    dmarc: str | None = Field(default=None, max_length=32)


class ScoreRequest(BaseModel):
    """Strict, bounded DTO from the Gmail add-on (no raw MIME / full bodies)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: str = Field(..., max_length=LIMITS.SCHEMA_VERSION_MAX_LEN)
    message_id: str | None = Field(default=None, max_length=LIMITS.MESSAGE_ID_MAX_LEN)
    thread_id: str | None = Field(default=None, max_length=LIMITS.THREAD_ID_MAX_LEN)
    from_email: str = Field(..., min_length=1, max_length=LIMITS.EMAIL_MAX_LEN)
    reply_to: str | None = Field(default=None, max_length=LIMITS.EMAIL_MAX_LEN)
    display_name: str | None = Field(default=None, max_length=LIMITS.DISPLAY_NAME_MAX_LEN)
    subject: str = Field(default="", max_length=LIMITS.SUBJECT_MAX_LEN)
    snippet: str = Field(default="", max_length=LIMITS.SNIPPET_MAX_LEN)
    urls: list[str] = Field(default_factory=list, max_length=LIMITS.MAX_URL_ITEMS)
    attachments: list[AttachmentRef] = Field(
        default_factory=list,
        max_length=LIMITS.MAX_ATTACHMENTS,
    )
    authentication: MessageAuthentication | None = None

    @field_validator("schema_version")
    @classmethod
    def schema_version_supported(cls, v: str) -> str:
        if v != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema_version {v!r}; only {SCHEMA_VERSION!r} is accepted.",
            )
        return v

    @field_validator("urls")
    @classmethod
    def urls_bounded_and_non_empty_items(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                raise ValueError("urls must not contain empty strings.")
            if len(s) > LIMITS.URL_MAX_LEN:
                raise ValueError(f"Each url must be at most {LIMITS.URL_MAX_LEN} characters.")
            out.append(s)
        return out


class SignalBreakdown(BaseModel):
    """Per-signal raw severity (0–100) before engine weights are applied in the merge."""

    model_config = ConfigDict(extra="forbid")

    headers: float = Field(0.0, ge=0.0)
    sender: float = Field(0.0, ge=0.0)
    urls: float = Field(0.0, ge=0.0)
    urgency: float = Field(0.0, ge=0.0)
    attachments: float = Field(0.0, ge=0.0)
    reputation_overlay: float = Field(0.0, ge=0.0)


class ReputationSummary(BaseModel):
    """Structured reputation slot; populated in Phase 3 when providers run."""

    model_config = ConfigDict(extra="forbid")

    contributed: bool = False
    providers: dict[str, str] = Field(default_factory=dict)


class ScoreResponse(BaseModel):
    """Scoring API response — contract shared with the Gmail card renderer."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, min_length=1)
    score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: list[str] = Field(..., max_length=LIMITS.MAX_REASONS)
    signals: SignalBreakdown
    reputation: ReputationSummary
    reputation_notice: str = Field(
        ...,
        max_length=512,
        description="Human-readable notice about reputation participation.",
    )

    @field_validator("reasons")
    @classmethod
    def reasons_nonempty_strings_bounded(cls, v: list[str]) -> list[str]:
        for r in v:
            if not r or not r.strip():
                raise ValueError("reasons must be non-empty strings.")
            if len(r) > LIMITS.REASON_MAX_LEN:
                raise ValueError(f"Each reason must be at most {LIMITS.REASON_MAX_LEN} characters.")
        return v


def verdict_from_score(score: int) -> Verdict:
    if score <= 39:
        return Verdict.LOW_RISK
    if score <= 69:
        return Verdict.SUSPICIOUS
    return Verdict.HIGH_RISK
