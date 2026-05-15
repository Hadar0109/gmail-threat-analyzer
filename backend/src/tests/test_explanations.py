"""Explanation layer tests.

Responsible for mapping, synthesis, categorization, severity, and verdict summaries.
Does not test scoring weights or verdict boundaries (see other modules).
"""

from __future__ import annotations

from app.explain.presenter import build_score_explanation
from app.explain.resolver import resolve_reason
from app.explain.synthesis import classify_signal, synthesize_findings
from app.explain.types import ExplanationCategory, ExplanationSeverity, MAX_KEY_FINDINGS
from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import score_message


def test_spf_fail_hidden_from_main_card() -> None:
    spec = resolve_reason(
        "SPF result was 'fail' (message did not pass this authentication check).",
    )
    row = classify_signal(
        "SPF result was 'fail' (message did not pass this authentication check).",
        spec,
    )
    assert row.tier.value == "technical"
    assert "SPF" not in spec.message


def test_safe_browsing_synthesized_once() -> None:
    technical = [
        "Google Safe Browsing matched at least one URL against a known threat list.",
        "Link host 'evil.example' is outside the sender domain ('acme.com').",
        "URL path resembles a login or verification endpoint.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    out = synthesize_findings(resolved, verdict=Verdict.DANGEROUS)
    assert len(out.key_findings) <= MAX_KEY_FINDINGS
    assert len(out.key_findings) >= 1
    assert out.key_findings[0].severity == "critical"
    messages = " ".join(f.message for f in out.key_findings).lower()
    assert "unsafe" in messages or "sign-in" in messages


def test_many_urgency_signals_merge_to_one_finding() -> None:
    technical = [
        "Message language stresses urgency.",
        "Demands immediate action.",
        "Uses time-pressure phrasing.",
        "Warns about suspicious activity or login.",
    ]
    resolved = [classify_signal(t, resolve_reason(t)) for t in technical]
    out = synthesize_findings(resolved, verdict=Verdict.SUSPICIOUS)
    pressure = [f for f in out.key_findings if f.theme == "pressure_tactics"]
    assert len(pressure) == 1
    assert "pressure" in pressure[0].message.lower()


def test_build_score_explanation_caps_key_findings() -> None:
    technical = [
        "SPF result was 'fail' (message did not pass this authentication check).",
        "Message language stresses urgency.",
        "Google Safe Browsing matched at least one URL against a known threat list.",
        "Reply-To domain (evil.com) differs from From domain (acme.com), "
        "which is common in impersonation and BEC-style mail.",
        "Potentially executable attachment metadata: 'invoice.exe'.",
    ]
    out = build_score_explanation(technical, Verdict.DANGEROUS)
    assert len(out.key_findings) <= MAX_KEY_FINDINGS
    assert len(out.reasons) <= MAX_KEY_FINDINGS
    assert out.reasons == [f.message for f in out.key_findings]
    assert out.detail_sections


def test_verdict_summaries_calmer_tone() -> None:
    for verdict, needle in (
        (Verdict.SAFE, "fine"),
        (Verdict.SUSPICIOUS, "unusual"),
        (Verdict.DANGEROUS, "warning"),
        (Verdict.CRITICAL, "unsafe"),
    ):
        out = build_score_explanation([], verdict)
        assert needle in out.verdict_guidance.summary.lower()


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
    assert len(out.explanation.key_findings) <= MAX_KEY_FINDINGS
    assert out.reasons == [f.message for f in out.explanation.key_findings]
    joined = " ".join(out.reasons).lower()
    assert "spf" not in joined
    assert "dkim" not in joined


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
