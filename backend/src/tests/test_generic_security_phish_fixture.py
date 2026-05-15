"""Regression: generic security-team verify-login phish reaches at least Suspicious."""

from __future__ import annotations

from app.schemas import Verdict
from app.scoring.engine import score_message
from tests.fixture_corpus import iter_fixtures


def test_generic_security_verify_login_fixture_not_safe() -> None:
    fixture = next(f for f in iter_fixtures("phishing") if f.id == "generic_security_verify_login")
    out = score_message(fixture.request)
    assert out.verdict != Verdict.SAFE
    assert out.score >= 29
    assert fixture.expected_score_min is not None
    assert out.score >= fixture.expected_score_min
