"""Explanation layer tests.

Responsible for mapping, categorization, severity, and verdict summaries.
Does not test scoring weights or verdict boundaries (see other modules).
"""

from __future__ import annotations

from app.explain.presenter import build_score_explanation
from app.explain.resolver import resolve_reason
from app.explain.types import ExplanationCategory, ExplanationSeverity
from app.schemas import Verdict
from app.scoring.engine import score_message
from app.schemas import ScoreRequest
from app.constants import SCHEMA_VERSION


def test_spf_fail_maps_to_plain_sender_language() -> None:
    spec = resolve_reason(
        "SPF result was 'fail' (message did not pass this authentication check).",
    )
    assert spec.category == ExplanationCategory.SENDER_IDENTITY
    assert spec.severity == ExplanationSeverity.HIGH
    assert "verify" in spec.message.lower()
    assert "SPF" not in spec.message


def test_safe_browsing_maps_to_reputation_critical() -> None:
    spec = resolve_reason(
        "Google Safe Browsing matched at least one URL against a known threat list.",
    )
    assert spec.category == ExplanationCategory.REPUTATION
    assert spec.severity == ExplanationSeverity.CRITICAL
    assert spec.guidance is not None


def test_external_link_pattern_user_friendly() -> None:
    spec = resolve_reason(
        "Link host 'evil.example' is outside the sender domain ('acme.com').",
    )
    assert spec.category == ExplanationCategory.LINKS_WEBSITES
    assert "unsafe" in spec.message.lower() or "link" in spec.message.lower()


def test_build_score_explanation_groups_by_category() -> None:
    technical = [
        "SPF result was 'fail' (message did not pass this authentication check).",
        "Message language stresses urgency.",
        "Google Safe Browsing matched at least one URL against a known threat list.",
    ]
    out = build_score_explanation(technical, Verdict.DANGEROUS)
    assert out.verdict_guidance.summary
    assert out.verdict_guidance.recommended_action
    assert len(out.groups) >= 2
    categories = {g.category for g in out.groups}
    assert "sender_identity" in categories
    assert "reputation_warnings" in categories
    assert out.reasons == [item.message for item in out.items]


def test_verdict_summaries_per_band() -> None:
    for verdict, needle in (
        (Verdict.SAFE, "legitimate"),
        (Verdict.SUSPICIOUS, "unusual"),
        (Verdict.DANGEROUS, "phishing"),
        (Verdict.CRITICAL, "malicious"),
    ):
        out = build_score_explanation([], verdict)
        assert needle in out.verdict_guidance.summary.lower()


def test_score_response_includes_structured_explanation() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "ceo@free-mail.example",
            "display_name": "ACME CEO",
            "reply_to": "pay@other.net",
            "subject": "Urgent wire transfer",
            "snippet": "Please wire transfer today immediately.",
            "authentication": {"spf": "fail", "dkim": "pass", "dmarc": "pass"},
        },
    )
    out = score_message(req)
    assert out.explanation.verdict_guidance.summary
    assert out.explanation.items
    assert out.reasons == out.explanation.reasons
    for reason in out.reasons:
        assert "SPF" not in reason
        assert "DKIM" not in reason


def test_deterministic_explanation_for_same_payload() -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "a@example.com",
        "subject": "Verify your account now",
        "snippet": "Click here to verify your login",
        "urls": ["http://192.0.2.1/login"],
    }
    a = score_message(ScoreRequest.model_validate(payload))
    b = score_message(ScoreRequest.model_validate(payload))
    assert a.explanation.model_dump() == b.explanation.model_dump()
