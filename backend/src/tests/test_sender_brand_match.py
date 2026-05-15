"""Sender–brand structural alignment tests."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.engine import score_message
from app.scoring.parsing.brands import extract_brand_mentions, load_brand_registry
from app.scoring.parsing.emails import parse_email_address
from app.scoring.parsing.sender_brand_match import (
    sender_aligned_with_brand,
    sender_structurally_reflects_brand,
)
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation


def _brand(brand_id: str):
    for b in load_brand_registry():
        if b.id == brand_id:
            return b
    raise AssertionError(f"brand {brand_id!r} missing")


def test_official_domain_aligned() -> None:
    brand = _brand("linkedin")
    parsed = parse_email_address("notifications@linkedin.com")
    assert parsed is not None
    assert sender_aligned_with_brand(brand, parsed.domain, parsed=parsed)


def test_local_part_dot_segment_aligned() -> None:
    brand = _brand("linkedin")
    parsed = parse_email_address("service.linkedin@mail.com")
    assert parsed is not None
    assert sender_structurally_reflects_brand(parsed, brand)


def test_subdomain_label_hyphen_aligned() -> None:
    brand = _brand("linkedin")
    parsed = parse_email_address("support@emails.linkedin-security.com")
    assert parsed is not None
    assert sender_structurally_reflects_brand(parsed, brand)


def test_lookalike_registrable_not_structurally_aligned() -> None:
    brand = _brand("paypal")
    parsed = parse_email_address("billing@paypa1-security.com")
    assert parsed is not None
    assert not sender_structurally_reflects_brand(parsed, brand)


def test_homoglyph_label_not_structurally_aligned() -> None:
    brand = _brand("paypal")
    parsed = parse_email_address("alerts@paypaI-security.com")
    assert parsed is not None
    assert not sender_structurally_reflects_brand(parsed, brand)


def test_microsoft_lookalike_login_domain_not_aligned() -> None:
    brand = _brand("microsoft")
    parsed = parse_email_address("security@micros0ft-login.net")
    assert parsed is not None
    assert not sender_structurally_reflects_brand(parsed, brand)


def test_github_phishing_ru_not_structurally_aligned() -> None:
    brand = _brand("github")
    parsed = parse_email_address("alerts@github-alerts-secure.ru")
    assert parsed is not None
    assert not sender_structurally_reflects_brand(parsed, brand)


def test_linkedin_notification_no_brand_mismatch_finding() -> None:
    chunk, findings = evaluate_brand_impersonation(
        ScoreRequest.model_validate(
            {
                "schema_version": SCHEMA_VERSION,
                "from_email": "notifications@linkedin.com",
                "display_name": "LinkedIn",
                "subject": "You have a new connection request",
                "snippet": "View the request on LinkedIn.",
            },
        ),
    )
    assert chunk.points == 0.0
    assert not any(f.tag == "brand_mention_foreign_sender" for f in findings)
    assert not any(f.tag == "display_name_brand_mismatch" for f in findings)


def test_service_paypal_no_foreign_sender_finding() -> None:
    chunk, findings = evaluate_brand_impersonation(
        ScoreRequest.model_validate(
            {
                "schema_version": SCHEMA_VERSION,
                "from_email": "service@paypal.com",
                "subject": "Your PayPal receipt",
                "snippet": "Thanks for your PayPal payment.",
            },
        ),
    )
    assert not any(f.tag == "brand_mention_foreign_sender" for f in findings)


def test_spoof_service_domain_still_flags() -> None:
    chunk, findings = evaluate_brand_impersonation(
        ScoreRequest.model_validate(
            {
                "schema_version": SCHEMA_VERSION,
                "from_email": "service@secure-payments-portal.click",
                "subject": "PayPal account action required",
                "snippet": "Sign in to your PayPal account.",
            },
        ),
    )
    assert chunk.points >= 28.0
    assert any(
        f.tag in {"brand_mention_foreign_sender", "display_name_brand_mismatch"}
        for f in findings
    )


def test_extract_brand_mentions_unchanged() -> None:
    hits = extract_brand_mentions("LinkedIn connection and GitHub PR")
    ids = {b.id for b in hits}
    assert "linkedin" in ids
    assert "github" in ids


def test_linkedin_service_mailbox_end_to_end_safe() -> None:
    out = score_message(
        ScoreRequest.model_validate(
            {
                "schema_version": SCHEMA_VERSION,
                "from_email": "service.linkedin@mail.com",
                "subject": "LinkedIn weekly digest",
                "snippet": "See what you missed on LinkedIn this week.",
                "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            },
        ),
    )
    assert out.verdict.value == "safe"
    assert out.score <= 28
