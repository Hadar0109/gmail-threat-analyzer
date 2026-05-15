"""Unit tests for brand impersonation and combo rules."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.combos.context import build_scoring_context
from app.scoring.combos.evaluator import evaluate_combos
from app.scoring.combos.rules import COMBO_RULES
from app.scoring.engine import score_message
from app.scoring.features.homoglyphs import domains_lookalike
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals_attachments import evaluate_attachments
from app.scoring.signals_urls import evaluate_urls
from app.scoring.types import SignalChunk


def _req(**kwargs: object) -> ScoreRequest:
    base: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "from_email": "billing@legit-corp.com",
    }
    base.update(kwargs)
    return ScoreRequest.model_validate(base)


def test_lookalike_helper_detects_paypa1() -> None:
    assert domains_lookalike("paypa1", "paypal")


def test_brand_display_name_free_mail() -> None:
    chunk, findings = evaluate_brand_impersonation(
        _req(
            from_email="Microsoft Security <security.alert@gmail.com>",
            display_name="Microsoft Security",
            subject="Unusual sign-in activity",
            snippet="Verify your account immediately.",
        ),
    )
    assert chunk.points >= 28.0
    tags = {f.tag for f in findings}
    assert "display_name_brand_mismatch" in tags


def test_brand_url_mismatch_paypal() -> None:
    chunk, findings = evaluate_brand_impersonation(
        _req(
            from_email="service@secure-payments-portal.click",
            subject="PayPal account action required",
            snippet="Sign in to your PayPal account to confirm.",
            urls=["https://paypa1-secure-login.top/account/verify"],
        ),
    )
    assert chunk.points >= 28.0
    assert any(f.tag == "brand_url_mismatch" for f in findings)


def test_archive_password_attachment() -> None:
    out = evaluate_attachments(
        _req(
            attachments=[
                {
                    "filename": "Invoice_March_password.zip",
                    "mime_type": "application/zip",
                },
            ],
        ),
    )
    assert out.points >= 26.0
    assert any("password" in r.lower() or "archive" in r.lower() for r in out.reasons)


def test_external_link_context() -> None:
    out = evaluate_urls(
        _req(
            from_email="team@acme.com",
            urls=["https://evil.example/login"],
        ),
    )
    assert out.points >= 24.0
    assert any(
        "outside" in r.lower() or "external" in r.lower() or "login" in r.lower()
        for r in out.reasons
    )


def test_combo_cred_external() -> None:
    req = _req(
        from_email="alert@unknown-sender.tk",
        subject="Verify your account now",
        snippet="Your session expired. Sign in again to restore access.",
        urls=["https://phish-host.example/verify"],
    )
    chunks = {
        "headers": SignalChunk(6.0, ()),
        "sender": SignalChunk(0.0, ()),
        "brand": SignalChunk(0.0, ()),
        "urls": evaluate_urls(req),
        "urgency": SignalChunk(30.0, ()),
        "attachments": SignalChunk(0.0, ()),
        "reputation_overlay": SignalChunk(0.0, ()),
    }
    ctx = build_scoring_context(req, chunks)
    combo = evaluate_combos(ctx)
    assert combo.boost > 0
    assert combo.matched_rule_ids
    assert combo.matched_rule_ids[0] in {
        "account_takeover_external",
        "cred_external",
        "generic_security_phish",
    }


def test_combo_rules_versioned() -> None:
    assert len(COMBO_RULES) >= 10
    ids = {r.id for r in COMBO_RULES}
    assert "auth_sender" in ids
    assert "invoice_attachment" in ids


def test_brand_spoof_fixture_scores_higher() -> None:
    out = score_message(
        _req(
            from_email="Microsoft Security <security.alert@gmail.com>",
            display_name="Microsoft Security",
            subject="Unusual sign-in activity detected",
            snippet="Verify your account immediately or access will be suspended.",
            urls=["https://microsoft-login-verify.xyz/secure"],
        ),
    )
    assert out.score >= 29
