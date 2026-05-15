"""Shared scoring types — Phase 2 / Phase B."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.scoring.features.extract import MessageFeatures

Severity = Literal["low", "medium", "high"]

__all__ = ["Finding", "MessageFeatures", "Severity", "SignalChunk"]


@dataclass(frozen=True)
class SignalChunk:
    """Single signal family: raw severity on a 0–100 scale plus explain strings."""

    points: float
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.points < 0 or self.points > 100:
            raise ValueError("SignalChunk.points must be within 0..100.")


@dataclass(frozen=True, slots=True)
class Finding:
    """Atomic detector output for combo rules and explainability."""

    tag: str
    severity: Severity
    reason: str
    evidence_ref: str | None = None
