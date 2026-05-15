"""Table-driven scoring tests — Phase 2 + Step 6."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.constants import SCHEMA_VERSION
from app.reputation.providers import ReputationRunResult
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import apply_critical_cap_for_urgency_isolation, score_message


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "billing@legit-corp.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_minimal_request_safe_band() -> None:
    out = score_message(_req())
    assert out.score <= 28
    assert out.verdict == Verdict.SAFE
    assert out.signals.headers > 0
    assert out.reputation.contributed is False


def test_headers_missing_authentication() -> None:
    """No authentication block — conservative baseline only."""
    out = score_message(_req())
    assert out.signals.headers == 6.0
    assert any("No SPF/DKIM/DMARC summary" in r for r in out.reasons)


def test_headers_empty_authentication_fields() -> None:
    out = score_message(_req(authentication={"spf": None, "dkim": None, "dmarc": None}))
    assert out.signals.headers == 6.0


def test_headers_spf_fail() -> None:
    out = score_message(
        _req(authentication={"spf": "fail", "dkim": "pass", "dmarc": "pass"}),
    )
    assert out.signals.headers >= 20.0
    assert any("SPF" in r and "fail" in r for r in out.reasons)


def test_headers_dkim_fail() -> None:
    out = score_message(
        _req(authentication={"spf": "pass", "dkim": "fail", "dmarc": "pass"}),
    )
    assert out.signals.headers >= 20.0
    assert any("DKIM" in r and "fail" in r for r in out.reasons)


def test_headers_dmarc_fail() -> None:
    out = score_message(
        _req(authentication={"spf": "pass", "dkim": "pass", "dmarc": "fail"}),
    )
    assert out.signals.headers >= 20.0
    assert any("DMARC" in r and "fail" in r for r in out.reasons)


def test_headers_all_three_pass() -> None:
    out = score_message(
        _req(authentication={"spf": "pass", "dkim": "pass", "dmarc": "pass"}),
    )
    assert out.signals.headers == 2.0
    assert any("SPF, DKIM, and DMARC all reported pass" in r for r in out.reasons)


def test_reply_to_domain_mismatch_increases_score_and_explains() -> None:
    out = score_message(
        _req(
            from_email="team@acme.com",
            reply_to="payments@evil.com",
            subject="Hello",
        ),
    )
    assert any("Reply-To domain" in r for r in out.reasons)
    assert out.signals.sender >= 50.0


def test_no_reply_mismatch_when_same_domain() -> None:
    out = score_message(
        _req(
            from_email="team@acme.com",
            reply_to="support@acme.com",
        ),
    )
    assert not any("Reply-To domain" in r for r in out.reasons)


def test_reply_to_angle_addr_detects_domain_mismatch() -> None:
    out = score_message(
        _req(
            from_email="team@acme.com",
            reply_to="Payments <payee@other.net>",
        ),
    )
    assert any("Reply-To domain" in r for r in out.reasons)
    assert out.signals.sender >= 50.0


def test_ip_literal_url_surfaces_url_reason() -> None:
    out = score_message(_req(urls=["http://203.0.113.9/reset-password"]))
    assert out.signals.urls >= 40.0
    assert any("IP address" in r for r in out.reasons)


def test_urgency_lexicon_hits() -> None:
    out = score_message(
        _req(
            subject="Invoice overdue — immediate action",
            snippet="Please wire transfer today. Verify your account now.",
        ),
    )
    assert out.signals.urgency >= 18.0
    assert len(out.reasons) >= 1


def test_executable_attachment_metadata() -> None:
    out = score_message(
        _req(
            attachments=[
                {"filename": "report.pdf.exe", "mime_type": "application/x-msdownload"},
            ],
        ),
    )
    assert out.signals.attachments >= 70.0
    assert any("double extension" in r.lower() or "executable" in r.lower() for r in out.reasons)


def test_stacked_signals_can_reach_suspicious_band() -> None:
    """Combined local signals should cross the Safe/Suspicious boundary without reputation."""
    out = score_message(
        _req(
            from_email="ceo@trusted-brand.com",
            reply_to="handler@different.net",
            subject="Urgent wire transfer invoice due",
            snippet="Your account suspended. Click here to verify your identity immediately.",
            urls=["http://203.0.113.9/pay", "https://bit.ly/claim-prize"],
            attachments=[
                {"filename": "Invoice_cmd.scr", "mime_type": "application/x-msdownload"},
            ],
        ),
    )
    assert out.score >= 29
    assert out.verdict in {Verdict.SUSPICIOUS, Verdict.DANGEROUS, Verdict.CRITICAL}


def test_engine_completes_when_reputation_keys_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local scoring always runs; missing vendor keys must not break the request."""
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    out = score_message(
        _req(
            from_email="billing@legit-corp.com",
            urls=["https://example.com/invoice"],
        ),
    )
    assert out.reputation.providers["safe_browsing"] == "skipped_no_api_key"
    assert out.reputation.providers["virustotal"] == "skipped_no_api_key"
    assert out.signals.reputation_overlay == 0.0
    assert out.verdict == Verdict.SAFE


def test_auth_fail_with_suspicious_sender_boosts_score() -> None:
    """SPF/DKIM/DMARC failure plus Reply-To drift should exceed auth-only baseline."""
    out = score_message(
        _req(
            from_email="finance@vendor.com",
            reply_to="payee@other.net",
            authentication={"spf": "fail", "dkim": "pass", "dmarc": "pass"},
            subject="Payment update",
        ),
    )
    assert out.score >= 22
    assert any("Authentication failure together" in r for r in out.reasons)


def test_all_pass_dampens_urgency_without_strong_urls() -> None:
    """All-pass auth reduces urgency-only contribution when URLs/sender are quiet."""
    with_pass = score_message(
        _req(
            authentication={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            subject="Urgent wire transfer invoice due",
            snippet="Verify your account now. Immediate action required.",
            urls=[],
        ),
    )
    without = score_message(
        _req(
            subject="Urgent wire transfer invoice due",
            snippet="Verify your account now. Immediate action required.",
            urls=[],
        ),
    )
    assert with_pass.signals.urgency < without.signals.urgency
    assert any("weighted more cautiously" in r for r in with_pass.reasons)


def test_reputation_malicious_floor_raises_score(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    fake = ReputationRunResult(
        overlay_points=84.0,
        reasons=("Google Safe Browsing matched at least one URL against a known threat list.",),
        contributed=True,
        providers={"safe_browsing": "threat", "virustotal": "skipped_no_api_key"},
        notice_kind="reputation_risk",
    )
    with patch("app.scoring.engine.run_reputation_checks", return_value=fake):
        out = score_message(
            _req(from_email="user@example.com", urls=["https://phish.example/login"]),
        )
    assert out.score >= 55
    assert out.verdict in {Verdict.SUSPICIOUS, Verdict.DANGEROUS, Verdict.CRITICAL}
    assert any("External reputation reported high-severity" in r for r in out.reasons)


def test_critical_cap_applies_for_urgency_isolation_profile() -> None:
    rep = ReputationRunResult(
        overlay_points=0.0,
        reasons=(),
        contributed=False,
        providers={"safe_browsing": "skipped_no_api_key", "virustotal": "skipped_no_api_key"},
        notice_kind="local_only",
    )
    total, capped = apply_critical_cap_for_urgency_isolation(
        80.0,
        rep=rep,
        urgency_points=60.0,
        url_points=5.0,
        sender_points=10.0,
    )
    assert capped is True
    assert total == 77.0


def test_critical_cap_skips_when_reputation_demands_floor() -> None:
    rep = ReputationRunResult(
        overlay_points=84.0,
        reasons=(),
        contributed=True,
        providers={"safe_browsing": "threat", "virustotal": "skipped_no_api_key"},
        notice_kind="reputation_risk",
    )
    total, capped = apply_critical_cap_for_urgency_isolation(
        82.0,
        rep=rep,
        urgency_points=90.0,
        url_points=0.0,
        sender_points=0.0,
    )
    assert capped is False
    assert total == 82.0
