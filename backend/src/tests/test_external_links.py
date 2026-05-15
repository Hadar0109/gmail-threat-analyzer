"""External link scoring and explanation tests."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.explain.brief_copy import SENTENCE_LIBRARY, select_brief_sentences
from app.explain.detail_copy import LINK_EXTERNAL_HOST, build_detail_groups
from app.explain.presenter import build_score_explanation
from app.explain.resolver import resolve_reason
from app.explain.synthesis import classify_signal
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import score_message
from app.scoring.signals.urls import evaluate_urls, url_tags


def _req(**kwargs: object) -> ScoreRequest:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "team@acme.com",
        "subject": "Hello",
        "snippet": "See our updates.",
    }
    payload.update(kwargs)
    return ScoreRequest.model_validate(payload)


def test_social_profile_links_are_neutral() -> None:
    req = _req(
        urls=[
            "https://www.facebook.com/acmecorp",
            "https://www.linkedin.com/company/acme",
            "https://twitter.com/acmecorp",
        ],
        authentication={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    )
    out = evaluate_urls(req)
    assert out.points == 0.0
    assert "external_link" not in url_tags(req)
    assert not any("outside the sender domain" in r for r in out.reasons)


def test_external_link_requires_url_risk_context() -> None:
    req = _req(urls=["https://partner.example/info"])
    tags = url_tags(req)
    assert "external_link" not in tags
    assert evaluate_urls(req).points == 0.0


def test_external_link_with_login_path_still_flags() -> None:
    req = _req(urls=["https://evil.example/login"])
    out = evaluate_urls(req)
    assert "external_link" in url_tags(req)
    assert "login_like_path" in url_tags(req)
    assert out.points >= 24.0
    assert any("outside the sender domain" in r for r in out.reasons)


def test_phishing_fixture_still_scores_with_off_domain_login() -> None:
    out = score_message(
        _req(
            subject="Verify your account now",
            snippet="Please verify your login at the link below.",
            urls=["https://secure-account-check-example.com/login"],
        ),
    )
    assert "login_like_path" in url_tags(
        _req(urls=["https://secure-account-check-example.com/login"]),
    )
    assert out.score >= 20


def test_external_domain_reason_not_on_main_brief() -> None:
    technical = [
        "Link host 'evil.example' is outside the sender domain ('acme.com') "
        "and shows additional link risk cues.",
        "URL path resembles a login or verification endpoint.",
    ]
    out = build_score_explanation(technical, Verdict.SUSPICIOUS)
    joined = " ".join(out.brief_sentences).lower()
    assert "outside" not in joined
    assert "organization" not in joined
    assert SENTENCE_LIBRARY["external_sign_in"] in out.brief_sentences


def test_external_domain_only_in_technical_details() -> None:
    technical = [
        "Link host 'evil.example' is outside the sender domain ('acme.com') "
        "and shows additional link risk cues.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    brief = select_brief_sentences(resolved, verdict=Verdict.SUSPICIOUS)
    assert not brief
    groups = build_detail_groups(resolved, technical, reputation=None, authentication=None, signals=None)
    link_group = next((g for g in groups if g.group_id == "link_checks"), None)
    assert link_group is not None
    assert LINK_EXTERNAL_HOST in link_group.items


def test_redirect_chain_triggers_external_link() -> None:
    req = _req(urls=["https://evil.example/redirect?u=https://evil.example/claim"])
    tags = url_tags(req)
    assert "nested_url" in tags
    assert "external_link" in tags
    assert evaluate_urls(req).points >= 35.0


def test_marketing_social_fixture_stays_safe_band() -> None:
    req = _req(
        subject="Follow Acme on social media",
        snippet="Connect with us on Facebook, LinkedIn, and X for updates.",
        urls=[
            "https://www.facebook.com/acmecorp",
            "https://www.linkedin.com/company/acme",
            "https://twitter.com/acmecorp",
        ],
        authentication={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    )
    out = score_message(req)
    assert out.verdict.value == "safe"
    assert "external_link" not in url_tags(req)
