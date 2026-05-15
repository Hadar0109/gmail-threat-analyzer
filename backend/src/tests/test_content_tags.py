"""Unit tests for categorized content-tag detectors."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.signals.content import evaluate_content
from app.scoring.signals.content import credential as credential_mod
from app.scoring.signals.content import financial as financial_mod
from app.scoring.signals.content import urgency as urgency_mod


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "billing@legit-corp.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_financial_category_cap() -> None:
    capped = financial_mod.detect(
        _req(
            subject="wire transfer ACH SWIFT bank account update payment details invoice due",
            snippet="wire transfer ACH SWIFT",
        ),
    )
    assert capped.points <= financial_mod.CAP
    assert capped.points > 0.0


def test_urgency_category_cap() -> None:
    out = urgency_mod.detect(
        _req(
            subject="Urgent immediate action click here act now within 24 hours",
            snippet="time sensitive urgent urgently",
        ),
    )
    assert out.points <= urgency_mod.CAP


def test_credential_gated_without_corroboration() -> None:
    isolated = credential_mod.detect(
        _req(
            subject="Verify your account",
            snippet="Session expired. Unusual sign-in detected.",
            urls=[],
        ),
    )
    assert isolated.points <= credential_mod.CAP_ISOLATED


def test_credential_allows_higher_with_urls() -> None:
    with_urls = credential_mod.detect(
        _req(
            subject="Verify your account",
            snippet="Session expired. Unusual sign-in detected.",
            urls=["https://evil.example/login"],
        ),
    )
    without = credential_mod.detect(
        _req(
            subject="Verify your account",
            snippet="Session expired. Unusual sign-in detected.",
            urls=[],
        ),
    )
    assert with_urls.points >= without.points


def test_evaluate_content_aggregates_multiple_categories() -> None:
    chunk = evaluate_content(
        _req(
            subject="Invoice overdue — immediate action",
            snippet="Please wire transfer today. Verify your account now.",
        ),
    )
    assert chunk.points >= 18.0
    assert len(chunk.reasons) >= 2


def test_evaluate_content_family_cap_at_100() -> None:
    chunk = evaluate_content(
        _req(
            subject=(
                "Urgent wire transfer invoice due security alert unauthorized access "
                "gift card bitcoin SSN W-2 package held customs fee IRS CEO request"
            ),
            snippet=(
                "Verify your account session expired one-time code verification code "
                "account compromised click here immediate action"
            ),
            urls=["https://evil.example/pay"],
        ),
    )
    assert chunk.points <= 100.0
