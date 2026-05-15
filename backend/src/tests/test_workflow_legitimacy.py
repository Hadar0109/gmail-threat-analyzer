"""Regression: legitimate multi-service workflow mail stays Safe."""

from __future__ import annotations

import pytest

from app.schemas import Verdict
from app.scoring.engine import score_message
from tests.fixture_corpus import iter_fixtures

_WORKFLOW_FIXTURE_IDS = (
    "comeet_teams_interview",
    "calendly_zoom_invite",
    "google_meet_invite",
    "github_notification",
    "stripe_receipt_tracking",
    "paypal_receipt_tracking",
)


@pytest.mark.parametrize("fixture_id", _WORKFLOW_FIXTURE_IDS)
def test_workflow_benign_fixtures_safe(fixture_id: str) -> None:
    fixture = next(f for f in iter_fixtures("benign") if f.id == fixture_id)
    out = score_message(fixture.request)
    assert out.verdict == Verdict.SAFE, f"{fixture_id}: {out.score} {out.verdict} {out.reasons}"
    if fixture.expected_score_max is not None:
        assert out.score <= fixture.expected_score_max


def test_comeet_teams_not_brand_impersonation() -> None:
    fixture = next(f for f in iter_fixtures("benign") if f.id == "comeet_teams_interview")
    out = score_message(fixture.request)
    assert out.score < 29
    joined = " ".join(out.reasons).lower()
    assert "brand_url_mismatch" not in joined
    assert "brand impersonation" not in joined
