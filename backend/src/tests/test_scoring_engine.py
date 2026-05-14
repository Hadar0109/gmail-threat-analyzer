"""Table-driven scoring tests — Phase 2."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest, Verdict
from app.scoring.engine import score_message


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "billing@legit-corp.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_minimal_request_low_risk_band() -> None:
    out = score_message(_req())
    assert out.score <= 25
    assert out.verdict == Verdict.LOW_RISK
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
    assert out.signals.urgency >= 24.0
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
    """Combined local signals should be able to cross the 40-point verdict boundary without reputation."""
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
    assert out.score >= 40
    assert out.verdict in {Verdict.SUSPICIOUS, Verdict.HIGH_RISK}
