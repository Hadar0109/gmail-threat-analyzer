"""Phase 2 — legitimacy context and reputation floor rework."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.constants import SCHEMA_VERSION
from app.reputation.providers import ReputationRunResult
from app.schemas import ScoreRequest, Verdict
from app.scoring.aggregate import (
    apply_reputation_floor,
    effective_reputation_overlay_points,
    reputation_requires_severity_floor,
)
from app.scoring.engine import score_message
from app.scoring.legitimacy import compute_legitimacy
from app.scoring.combos.context import auth_band
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.types import SignalChunk
from tests.fixture_corpus import iter_fixtures


def _apple_req(**extra: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "no_reply@email.apple.com",
        "display_name": "Apple",
        "subject": "Your receipt from Apple",
        "snippet": "Thank you for your purchase. View your receipt.",
        "urls": [
            "https://support.apple.com/bill",
            "http://email.apple.com/ws/click",
            "https://account.apple.com/manage",
        ],
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    }
    base.update(extra)
    return ScoreRequest.model_validate(base)


def _vt_malicious_rep() -> ReputationRunResult:
    return ReputationRunResult(
        overlay_points=68.0,
        reasons=("VirusTotal reports multiple antivirus engines flagging at least one URL as malicious.",),
        contributed=True,
        providers={"safe_browsing": "clean", "virustotal": "malicious"},
        notice_kind="reputation_risk",
    )


def test_apple_receipt_legitimacy_tier_trusted() -> None:
    req = _apple_req()
    auth = auth_band(req)
    brand, findings = evaluate_brand_impersonation(req)
    leg = compute_legitimacy(req, auth, brand, findings)
    assert leg.tier == "trusted_transactional"


def test_vt_overlay_dampened_for_trusted_transactional() -> None:
    rep = _vt_malicious_rep()
    req = _apple_req()
    auth = auth_band(req)
    brand, findings = evaluate_brand_impersonation(req)
    leg = compute_legitimacy(req, auth, brand, findings)
    assert effective_reputation_overlay_points(rep, leg) < rep.overlay_points


def test_vt_only_does_not_require_floor_on_trusted_apple() -> None:
    rep = _vt_malicious_rep()
    req = _apple_req()
    from app.scoring.engine import score_message as _  # noqa: F401
    from app.scoring.signals_headers import evaluate_headers
    from app.scoring.signals_sender import evaluate_sender
    from app.scoring.signals_urls import evaluate_urls
    from app.scoring.signals_urgency import evaluate_urgency
    from app.scoring.signals_attachments import evaluate_attachments

    auth = auth_band(req)
    brand, findings = evaluate_brand_impersonation(req)
    leg = compute_legitimacy(req, auth, brand, findings)
    chunks = {
        "headers": evaluate_headers(req),
        "sender": evaluate_sender(req),
        "brand": brand,
        "urls": evaluate_urls(req, legitimacy=leg),
        "urgency": evaluate_urgency(req),
        "attachments": evaluate_attachments(req),
        "reputation_overlay": SignalChunk(68.0),
    }
    assert reputation_requires_severity_floor(rep, legitimacy=leg, chunks=chunks) is False


def test_apple_receipt_without_vt_stays_safe() -> None:
    fixture = next(f for f in iter_fixtures("benign") if f.id == "apple_receipt_auth_pass")
    out = score_message(fixture.request)
    assert out.verdict == Verdict.SAFE
    assert out.score <= 28


def test_apple_receipt_vt_noise_not_dangerous(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = next(f for f in iter_fixtures("benign") if f.id == "apple_receipt_vt_noise")
    fake = _vt_malicious_rep()
    with patch("app.scoring.engine.run_reputation_checks", return_value=fake):
        out = score_message(fixture.request)
    assert out.verdict != Verdict.DANGEROUS
    assert out.score <= 52
    assert any("trusted transactional" in r.lower() for r in out.reasons)


def test_phishing_generic_still_suspicious_after_phase2() -> None:
    fixture = next(f for f in iter_fixtures("phishing") if f.id == "generic_security_verify_login")
    out = score_message(fixture.request)
    assert out.verdict != Verdict.SAFE
    assert out.score >= 29


def test_hostile_vt_still_floors(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _vt_malicious_rep()
    chunks = {
        "headers": SignalChunk(6.0),
        "sender": SignalChunk(0.0),
        "brand": SignalChunk(0.0),
        "urls": SignalChunk(24.0),
        "urgency": SignalChunk(10.0),
        "attachments": SignalChunk(0.0),
        "reputation_overlay": SignalChunk(68.0),
    }
    total, floored = apply_reputation_floor(10.0, fake, legitimacy=None, chunks=chunks)
    assert floored is True
    assert total >= 55
