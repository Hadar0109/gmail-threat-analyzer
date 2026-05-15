"""API data contracts.

Responsible for Pydantic request/response models and verdict mapping helpers.
Does not run detectors or aggregate scores.
"""
from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.constants import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS
from app.limits import LIMITS


class Verdict(StrEnum):
    """Four-band verdict from the final 0–100 score (Step 6)."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class LinkRef(BaseModel):
    """Optional anchor metadata (schema 1.2) for display-text vs destination checks."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(..., max_length=LIMITS.URL_MAX_LEN)
    display_text: str | None = Field(default=None, max_length=512)


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
    issued_at: int | None = Field(
        default=None,
        description="Client unix time in milliseconds; included in signed body for replay control.",
    )
    request_id: str | None = Field(
        default=None,
        max_length=LIMITS.REQUEST_ID_MAX_LEN,
        description="Unique id per request (UUID); included in signed body for replay control.",
    )
    message_id: str | None = Field(default=None, max_length=LIMITS.MESSAGE_ID_MAX_LEN)
    thread_id: str | None = Field(default=None, max_length=LIMITS.THREAD_ID_MAX_LEN)
    from_email: str = Field(..., min_length=1, max_length=LIMITS.EMAIL_MAX_LEN)
    reply_to: str | None = Field(default=None, max_length=LIMITS.EMAIL_MAX_LEN)
    display_name: str | None = Field(default=None, max_length=LIMITS.DISPLAY_NAME_MAX_LEN)
    subject: str = Field(default="", max_length=LIMITS.SUBJECT_MAX_LEN)
    snippet: str = Field(default="", max_length=LIMITS.SNIPPET_MAX_LEN)
    body_text_for_scoring: str | None = Field(
        default=None,
        max_length=LIMITS.SNIPPET_MAX_LEN,
        description="Optional longer plain-text window for content heuristics (schema 1.2).",
    )
    urls: list[str] = Field(default_factory=list, max_length=LIMITS.MAX_URL_ITEMS)
    links: list[LinkRef] = Field(
        default_factory=list,
        max_length=LIMITS.MAX_URL_ITEMS,
        description="Optional structured links with display text (schema 1.2).",
    )
    content_flags: list[str] = Field(
        default_factory=list,
        max_length=32,
        description="Optional client-precomputed content hints (schema 1.2).",
    )
    attachments: list[AttachmentRef] = Field(
        default_factory=list,
        max_length=LIMITS.MAX_ATTACHMENTS,
    )
    authentication: MessageAuthentication | None = None

    @field_validator("schema_version")
    @classmethod
    def schema_version_supported(cls, v: str) -> str:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
            raise ValueError(
                f"Unsupported schema_version {v!r}; supported versions: {supported}.",
            )
        return v

    @field_validator("content_flags")
    @classmethod
    def content_flags_bounded(cls, v: list[str]) -> list[str]:
        for flag in v:
            if not flag or not flag.strip():
                raise ValueError("content_flags must not contain empty strings.")
            if len(flag) > 64:
                raise ValueError("Each content_flags entry must be at most 64 characters.")
        return v

    @field_validator("links")
    @classmethod
    def links_urls_non_empty(cls, v: list[LinkRef]) -> list[LinkRef]:
        for link in v:
            if not link.url.strip():
                raise ValueError("links must not contain empty url values.")
        return v

    @field_validator("issued_at")
    @classmethod
    def issued_at_sensible(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < 1_000_000_000_000:  # reject seconds-as-ms and garbage
            raise ValueError("issued_at must be a plausible unix time in milliseconds.")
        return v

    @field_validator("request_id")
    @classmethod
    def request_id_uuid(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        try:
            parsed = uuid.UUID(s)
        except ValueError as exc:
            raise ValueError("request_id must be a valid UUID.") from exc
        return str(parsed)

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
    """Structured reputation slot when providers run."""

    model_config = ConfigDict(extra="forbid")

    contributed: bool = False
    providers: dict[str, str] = Field(default_factory=dict)


class VerdictGuidance(BaseModel):
    """High-level verdict summary and recommended user action."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., max_length=LIMITS.REASON_MAX_LEN)
    recommended_action: str = Field(..., max_length=LIMITS.REASON_MAX_LEN)


class ExplanationItem(BaseModel):
    """One user-facing reason with category and severity."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., max_length=64)
    category_label: str = Field(..., max_length=128)
    severity: str = Field(..., max_length=16)
    message: str = Field(..., max_length=LIMITS.REASON_MAX_LEN)
    guidance: str | None = Field(default=None, max_length=LIMITS.REASON_MAX_LEN)


class ExplanationGroup(BaseModel):
    """Explanations grouped by category for card UI rendering."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., max_length=64)
    label: str = Field(..., max_length=128)
    items: list[ExplanationItem] = Field(default_factory=list)


class KeyFinding(BaseModel):
    """One synthesized finding for the main card (2–5 shown)."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., max_length=LIMITS.REASON_MAX_LEN)
    severity: str = Field(..., max_length=16)
    guidance: str | None = Field(default=None, max_length=LIMITS.REASON_MAX_LEN)
    theme: str = Field(default="", max_length=64)


class ExplanationDetailSection(BaseModel):
    """Collapsible detail section (technical / auth / reputation / signals)."""

    model_config = ConfigDict(extra="forbid")

    section_id: str = Field(..., max_length=64)
    label: str = Field(..., max_length=128)
    items: list[ExplanationItem] = Field(default_factory=list)


class ScoreExplanation(BaseModel):
    """Structured explainability payload derived from internal detector reasons."""

    model_config = ConfigDict(extra="forbid")

    checked_notice: str = Field(
        default="This email was checked.",
        max_length=LIMITS.REASON_MAX_LEN,
        description="Top-of-card confirmation that the message was analyzed.",
    )
    brief_sentences: list[str] = Field(
        default_factory=list,
        max_length=7,
        description="Short main-card copy from the fixed sentence library only.",
    )
    verdict_guidance: VerdictGuidance
    key_findings: list[KeyFinding] = Field(
        default_factory=list,
        max_length=5,
        description="Synthesized findings (for API consumers; not shown on the simple main card).",
    )
    detail_sections: list[ExplanationDetailSection] = Field(default_factory=list)
    items: list[ExplanationItem] = Field(
        default_factory=list,
        description="All resolved signals (for advanced/debug views).",
    )
    groups: list[ExplanationGroup] = Field(
        default_factory=list,
        description="Legacy grouped view; prefer brief_sentences on the main card.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        max_length=LIMITS.MAX_REASONS,
        description="Mirrors brief_sentences for backward-compatible clients.",
    )


class ScoreResponse(BaseModel):
    """Scoring API response — contract shared with the Gmail card renderer."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, min_length=1)
    score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: list[str] = Field(
        ...,
        max_length=LIMITS.MAX_REASONS,
        description="Plain-language reasons in display order (see explanation for structure).",
    )
    explanation: ScoreExplanation
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
    """Map integer score to verdict after all engine adjustments."""
    if score <= 28:
        return Verdict.SAFE
    if score <= 52:
        return Verdict.SUSPICIOUS
    if score <= 77:
        return Verdict.DANGEROUS
    return Verdict.CRITICAL
