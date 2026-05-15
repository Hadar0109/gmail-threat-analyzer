"""LLM provider result types — no scoring imports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

LlmCategory = Literal[
    "credential_theft",
    "financial_fraud",
    "malware_attachment",
    "impersonation",
    "urgency",
    "sensitive_info_request",
]

_VALID_CATEGORIES = frozenset(
    {
        "credential_theft",
        "financial_fraud",
        "malware_attachment",
        "impersonation",
        "urgency",
        "sensitive_info_request",
    },
)


class LlmStructuredAnalysis(BaseModel):
    """Validated model JSON from the LLM."""

    model_config = ConfigDict(extra="forbid")

    risk_points: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list, max_length=12)
    reasons: list[str] = Field(default_factory=list, max_length=8)
    should_not_override_reputation: bool = True

    @field_validator("categories")
    @classmethod
    def categories_known(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for c in v:
            s = str(c).strip().lower()
            if s in _VALID_CATEGORIES and s not in out:
                out.append(s)
        return out

    @field_validator("reasons")
    @classmethod
    def reasons_bounded(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for r in v:
            s = str(r).strip()
            if not s:
                continue
            out.append(s[:512])
            if len(out) >= 8:
                break
        return out


@dataclass(frozen=True)
class LlmProviderResult:
    """Outcome of one LLM inference attempt (or skip)."""

    status: str
    analysis: LlmStructuredAnalysis | None = None
    latency_ms: int = 0
    model: str = ""
