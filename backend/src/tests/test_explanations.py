"""Explanation layer tests."""

from __future__ import annotations

from app.explain.brief_copy import SENTENCE_LIBRARY, select_brief_sentences
from app.explain.detail_copy import LINK_NON_SECURE, build_detail_groups
from app.explain.presenter import build_score_explanation
from app.explain.resolver import resolve_reason
from app.explain.synthesis import classify_signal, synthesize_findings
from app.explain.types import MAX_KEY_FINDINGS
from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import score_message

_LIBRARY_TEXTS = frozenset(SENTENCE_LIBRARY.values())


def test_spf_fail_hidden_from_main_brief() -> None:
    technical = ["SPF result was 'fail' (message did not pass this authentication check)."]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    brief = select_brief_sentences(resolved, verdict=Verdict.SUSPICIOUS)
    assert not brief
    out = build_score_explanation(technical, Verdict.SUSPICIOUS)
    joined = " ".join(out.brief_sentences).lower()
    assert "spf" not in joined


def test_brief_sentences_only_from_library() -> None:
    technical = [
        "Google Safe Browsing matched at least one URL against a known threat list.",
        "URL path resembles a login or verification endpoint.",
        "Message language stresses urgency.",
    ]
    out = build_score_explanation(technical, Verdict.DANGEROUS)
    assert out.brief_sentences
    assert len(out.brief_sentences) <= 3
    for sentence in out.brief_sentences:
        assert sentence in _LIBRARY_TEXTS
    assert len(out.brief_sentences) == len(set(out.brief_sentences))


def test_sign_in_uses_external_link_sentence() -> None:
    technical = [
        "URL path resembles a login or verification endpoint.",
        "Asks to verify an account or identity.",
    ]
    out = build_score_explanation(technical, Verdict.SUSPICIOUS)
    assert SENTENCE_LIBRARY["external_sign_in"] in out.brief_sentences


def test_http_links_merged_in_details() -> None:
    technical = [
        "At least one URL uses HTTP instead of HTTPS.",
        "URL path resembles a login or verification endpoint.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    groups = build_detail_groups(resolved, technical, reputation=None, authentication=None, signals=None)
    link_group = next((g for g in groups if g.group_id == "links"), None)
    assert link_group is not None
    assert link_group.items.count(LINK_NON_SECURE) == 1
    assert "Login-style URL path detected" in link_group.items


def test_technical_auth_wording() -> None:
    technical = [
        "SPF result was 'fail' (message did not pass this authentication check).",
        "DKIM result was 'fail' (message did not pass this authentication check).",
    ]
    groups = build_detail_groups(
        [],
        technical,
        reputation=None,
        authentication=None,
        signals=None,
    )
    auth = next(g for g in groups if g.group_id == "authentication")
    joined = " | ".join(auth.items)
    assert "SPF validation failed for the sender domain" in joined
    assert "DKIM signature verification failed" in joined
    assert "could not be fully verified" not in joined.lower()


def test_reputation_group_separate_from_links() -> None:
    from app.schemas import ReputationSummary

    technical = [
        "At least one URL uses HTTP instead of HTTPS.",
        "Google Safe Browsing matched at least one URL against a known threat list.",
    ]
    groups = build_detail_groups(
        [],
        technical,
        reputation=ReputationSummary(
            contributed=True,
            providers={"safe_browsing": "threat", "virustotal": "clean"},
        ),
        authentication=None,
        signals=None,
    )
    links = next(g for g in groups if g.group_id == "links")
    rep = next(g for g in groups if g.group_id == "reputation")
    assert LINK_NON_SECURE in links.items
    assert "Google Safe Browsing" in " ".join(rep.items)
    assert "Safe Browsing" not in " ".join(links.items)


def test_attachment_technical_detail_includes_filename() -> None:
    technical = [
        "Filename suggests a double extension trick: 'invoice.pdf.exe'.",
        "Macro-enabled Office attachment: 'report.docm'.",
    ]
    groups = build_detail_groups(
        [],
        technical,
        reputation=None,
        authentication=None,
        signals=None,
    )
    att = next(g for g in groups if g.group_id == "attachments")
    joined = " ".join(att.items)
    assert "invoice.pdf.exe" in joined
    assert "report.docm" in joined


def test_signal_scores_hide_zero() -> None:
    from app.schemas import SignalBreakdown

    groups = build_detail_groups(
        [],
        [],
        reputation=None,
        authentication=None,
        signals=SignalBreakdown(
            headers=0.0,
            sender=55.0,
            urls=24.0,
            urgency=0.0,
            attachments=0.0,
            reputation_overlay=0.0,
        ),
    )
    sig = next(g for g in groups if g.group_id == "signal_scores")
    text = " ".join(sig.items)
    assert "Sender: 55" in text
    assert "Links: 24" in text
    assert "Attachments" not in text
    assert "Content" not in text


def test_safe_browsing_synthesized_once() -> None:
    technical = [
        "Google Safe Browsing matched at least one URL against a known threat list.",
        "Link host 'evil.example' is outside the sender domain ('acme.com').",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    synthesis = synthesize_findings(resolved, verdict=Verdict.DANGEROUS)
    assert len(synthesis.key_findings) <= MAX_KEY_FINDINGS
    assert len(synthesis.key_findings) >= 1


def test_build_score_explanation_has_grouped_details() -> None:
    technical = [
        "SPF result was 'fail' (message did not pass this authentication check).",
        "At least one URL uses HTTP instead of HTTPS.",
        "Google Safe Browsing matched at least one URL against a known threat list.",
    ]
    out = build_score_explanation(technical, Verdict.DANGEROUS)
    assert out.detail_groups
    auth = next((g for g in out.detail_groups if g.group_id == "authentication"), None)
    assert auth is not None
    assert any("SPF" in i for i in auth.items)


def test_safe_verdict_empty_brief() -> None:
    out = build_score_explanation([], Verdict.SAFE)
    assert out.brief_sentences == []


def test_score_response_synthesized_not_noisy() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "ceo@free-mail.example",
            "display_name": "ACME CEO",
            "reply_to": "pay@other.net",
            "subject": "Urgent wire transfer",
            "snippet": "Please wire transfer today immediately. Verify your account now.",
            "authentication": {"spf": "fail", "dkim": "pass", "dmarc": "pass"},
        },
    )
    out = score_message(req)
    assert len(out.explanation.brief_sentences) <= 3
    for sentence in out.explanation.brief_sentences:
        assert sentence in _LIBRARY_TEXTS
    joined = " ".join(out.explanation.brief_sentences).lower()
    assert "spf" not in joined


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
