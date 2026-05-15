"""Fixture corpus regression tests.

Responsible for benign/phishing fixture verdict bands and optional enforcement mode.
"""
from __future__ import annotations

import os

import pytest

from app.schemas import Verdict
from app.scoring.engine import score_message
from tests.fixture_corpus import FIXTURES_ROOT, LabeledFixture, all_fixtures, iter_fixtures

# Target phishing bands are enforced once Milestone 1 detectors land; until then CI
# records baseline scores without failing the suite.
_ENFORCE_PHISHING_TARGETS = os.environ.get("ENFORCE_PHISHING_FIXTURES", "").strip() == "1"


def _fixture_ids(items: list[LabeledFixture]) -> list[str]:
    return [f"{item.label}/{item.id}" for item in items]


_PHISHING = list(iter_fixtures("phishing"))
_BENIGN = list(iter_fixtures("benign"))
_ALL = all_fixtures()


def test_fixture_corpus_is_present() -> None:
    assert FIXTURES_ROOT.is_dir()
    assert len(_PHISHING) >= 8
    assert len(_BENIGN) >= 8


@pytest.mark.parametrize("fixture", _PHISHING, ids=_fixture_ids(_PHISHING))
def test_phishing_fixtures_meet_expected_verdict(fixture: LabeledFixture) -> None:
    if not _ENFORCE_PHISHING_TARGETS:
        pytest.skip("Set ENFORCE_PHISHING_FIXTURES=1 to enforce phishing target bands")
    out = score_message(fixture.request)
    assert out.verdict in fixture.expected_verdicts, (
        f"{fixture.id}: score={out.score} verdict={out.verdict.value} "
        f"expected one of {[v.value for v in fixture.expected_verdicts]}"
    )
    if fixture.expected_score_min is not None:
        assert out.score >= fixture.expected_score_min
    if fixture.expected_score_max is not None:
        assert out.score <= fixture.expected_score_max


@pytest.mark.parametrize("fixture", _PHISHING, ids=_fixture_ids(_PHISHING))
def test_phishing_fixtures_declare_target_band(fixture: LabeledFixture) -> None:
    """Phishing corpus entries must document a non-safe target verdict band."""
    assert fixture.expected_verdicts
    assert Verdict.SAFE not in fixture.expected_verdicts


@pytest.mark.parametrize("fixture", _PHISHING, ids=_fixture_ids(_PHISHING))
def test_phishing_fixture_baseline_recorded(fixture: LabeledFixture) -> None:
    """Always score phishing fixtures so PRs can diff baseline drift."""
    out = score_message(fixture.request)
    assert 0 <= out.score <= 100


@pytest.mark.parametrize("fixture", _BENIGN, ids=_fixture_ids(_BENIGN))
def test_benign_fixtures_stay_within_expected_band(fixture: LabeledFixture) -> None:
    out = score_message(fixture.request)
    assert out.verdict in fixture.expected_verdicts, (
        f"{fixture.id}: score={out.score} verdict={out.verdict.value} "
        f"expected one of {[v.value for v in fixture.expected_verdicts]}"
    )
    if fixture.expected_score_min is not None:
        assert out.score >= fixture.expected_score_min
    if fixture.expected_score_max is not None:
        assert out.score <= fixture.expected_score_max


@pytest.mark.parametrize("fixture", _ALL, ids=_fixture_ids(_ALL))
def test_fixture_requests_validate(fixture: LabeledFixture) -> None:
    assert fixture.request.schema_version in {"1.1", "1.2"}
    assert fixture.request.from_email
