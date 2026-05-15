"""Golden tests at verdict band boundaries (28, 29, 52, 53, 77, 78)."""

from __future__ import annotations

from app.schemas import Verdict, verdict_from_score


def test_verdict_safe_upper_boundary() -> None:
    assert verdict_from_score(28) == Verdict.SAFE
    assert verdict_from_score(0) == Verdict.SAFE


def test_verdict_suspicious_lower_boundary() -> None:
    assert verdict_from_score(29) == Verdict.SUSPICIOUS


def test_verdict_suspicious_upper_boundary() -> None:
    assert verdict_from_score(52) == Verdict.SUSPICIOUS


def test_verdict_dangerous_lower_boundary() -> None:
    assert verdict_from_score(53) == Verdict.DANGEROUS


def test_verdict_dangerous_upper_boundary() -> None:
    assert verdict_from_score(77) == Verdict.DANGEROUS


def test_verdict_critical_lower_boundary() -> None:
    assert verdict_from_score(78) == Verdict.CRITICAL
