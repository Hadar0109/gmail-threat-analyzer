"""Shared scoring types — Phase 2."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SignalChunk:
    """Single signal family: raw severity on a 0–100 scale plus explain strings."""

    points: float
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.points < 0 or self.points > 100:
            raise ValueError("SignalChunk.points must be within 0..100.")
