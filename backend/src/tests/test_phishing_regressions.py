"""Gift-card, invoice-malware, and archive-invoice lures reach at least Suspicious."""

from __future__ import annotations

import pytest

from app.schemas import Verdict
from app.scoring.engine import score_message
from tests.fixture_corpus import iter_fixtures

_PHISHING_REGRESSION_IDS = (
    "gift_card_urgency",
    "invoice_executable",
    "archive_invoice_lure",
)


@pytest.mark.parametrize("fixture_id", _PHISHING_REGRESSION_IDS)
def test_phishing_regression_not_safe(fixture_id: str) -> None:
    fixture = next(f for f in iter_fixtures("phishing") if f.id == fixture_id)
    out = score_message(fixture.request)
    assert out.verdict != Verdict.SAFE
    assert out.score >= 29, f"{fixture_id} scored {out.score} ({out.verdict})"
