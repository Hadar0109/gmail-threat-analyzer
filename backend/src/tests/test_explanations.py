"""Explanation layer tests."""

from __future__ import annotations

from app.explain.brief_copy import SENTENCE_LIBRARY, select_brief_sentences
from app.explain.presenter import build_score_explanation
from app.explain.resolver import resolve_reason
from app.explain.synthesis import ResolvedSignal, classify_signal, synthesize_findings
from app.explain.types import MAX_KEY_FINDINGS, SynthesisTheme
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


def test_sign_in_cluster_maps_to_one_library_sentence() -> None:
    technical = [
        "URL path resembles a login or verification endpoint.",
        "Link host 'evil.example' is outside the sender domain ('acme.com').",
        "Asks to verify an account or identity.",
    ]
    out = build_score_explanation(technical, Verdict.SUSPICIOUS)
    unsafe = SENTENCE_LIBRARY["unsafe_links"]
    sensitive = SENTENCE_LIBRARY["sensitive_request"]
    assert unsafe in out.brief_sentences or sensitive in out.brief_sentences
    assert out.brief_sentences.count(unsafe) <= 1


def test_safe_browsing_synthesized_once() -> None:
    technical = [
        "Google Safe Browsing matched at least one URL against a known threat list.",
        "Link host 'evil.example' is outside the sender domain ('acme.com').",
        "URL path resembles a login or verification endpoint.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    synthesis = synthesize_findings(resolved, verdict=Verdict.DANGEROUS)
    assert len(synthesis.key_findings) <= MAX_KEY_FINDINGS
    assert len(synthesis.key_findings) >= 1


def test_many_urgency_signals_merge_to_one_finding() -> None:
    technical = [
        "Message language stresses urgency.",
        "Demands immediate action.",
        "Uses time-pressure phrasing.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    out = synthesize_findings(resolved, verdict=Verdict.SUSPICIOUS)
    pressure = [f for f in out.key_findings if f.theme == "pressure_tactics"]
    assert len(pressure) == 1


def test_build_score_explanation_has_more_details() -> None:
    technical = [
        "SPF result was 'fail' (message did not pass this authentication check).",
        "Google Safe Browsing matched at least one URL against a known threat list.",
    ]
    out = build_score_explanation(technical, Verdict.DANGEROUS)
    assert out.checked_notice
    assert out.reasons == out.brief_sentences
    assert out.detail_sections
    assert out.detail_sections[0].section_id == "more_details"
    detail_text = " ".join(i.message for i in out.detail_sections[0].items).lower()
    assert "spf" in detail_text or "fail" in detail_text


def test_safe_verdict_empty_brief() -> None:
    out = build_score_explanation([], Verdict.SAFE)
    assert out.checked_notice == "This email was checked."
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
