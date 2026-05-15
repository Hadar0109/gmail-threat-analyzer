"""
Live outbound calls to Google Safe Browsing and VirusTotal.

These tests are opt-in so CI and normal `pytest` runs stay offline:

  cd backend
  set RUN_REPUTATION_LIVE=1
  pytest src/tests/test_reputation_live.py -v

Put keys in `backend/.env` (see `.env.example`) or export them in the shell.
"""

from __future__ import annotations

import os

import httpx
import pytest

from app.bootstrap.env import load_backend_dotenv
from app.reputation.safebrowsing import check_safe_browsing
from app.reputation.virustotal import check_virustotal_urls
from app.schemas import SCHEMA_VERSION, ScoreRequest
from app.scoring.engine import score_message

pytestmark = pytest.mark.integration


def _live_enabled() -> bool:
    return os.getenv("RUN_REPUTATION_LIVE", "").strip().lower() in ("1", "true", "yes")


def _reload_dotenv() -> None:
    load_backend_dotenv()


def _sb_key() -> str | None:
    s = (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or "").strip()
    return s or None


def _vt_key() -> str | None:
    s = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
    return s or None


@pytest.fixture
def httpx_client() -> httpx.Client:
    with httpx.Client(
        timeout=httpx.Timeout(15.0, connect=5.0),
        follow_redirects=True,
    ) as c:
        yield c


@pytest.mark.skipif(not _live_enabled(), reason="Set RUN_REPUTATION_LIVE=1 for live reputation tests.")
def test_live_safe_browsing_clean_url(httpx_client: httpx.Client) -> None:
    _reload_dotenv()
    key = _sb_key()
    if not key:
        pytest.skip("GOOGLE_SAFE_BROWSING_API_KEY missing (backend/.env or environment).")
    res = check_safe_browsing(["https://www.google.com/"], key, client=httpx_client)
    assert res.status == "clean"
    assert res.threat_match is False


@pytest.mark.skipif(not _live_enabled(), reason="Set RUN_REPUTATION_LIVE=1 for live reputation tests.")
def test_live_safe_browsing_google_test_phishing_page(httpx_client: httpx.Client) -> None:
    """Official Google test page (social engineering list)."""
    _reload_dotenv()
    key = _sb_key()
    if not key:
        pytest.skip("GOOGLE_SAFE_BROWSING_API_KEY missing (backend/.env or environment).")
    res = check_safe_browsing(
        ["https://testsafebrowsing.appspot.com/s/phishing.html"],
        key,
        client=httpx_client,
    )
    assert res.status == "threat"
    assert res.threat_match is True


@pytest.mark.skipif(not _live_enabled(), reason="Set RUN_REPUTATION_LIVE=1 for live reputation tests.")
def test_live_virustotal_google_url(httpx_client: httpx.Client) -> None:
    _reload_dotenv()
    key = _vt_key()
    if not key:
        pytest.skip("VIRUSTOTAL_API_KEY missing (backend/.env or environment).")
    res = check_virustotal_urls(["https://www.google.com/"], key, client=httpx_client)
    assert res.status in {"clean", "not_found", "suspicious", "malicious"}


@pytest.mark.skipif(not _live_enabled(), reason="Set RUN_REPUTATION_LIVE=1 for live reputation tests.")
def test_live_score_engine_overlay_from_safe_browsing_threat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: overlay points and merged score reflect a Safe Browsing hit."""
    _reload_dotenv()
    key = _sb_key()
    if not key:
        pytest.skip("GOOGLE_SAFE_BROWSING_API_KEY missing (backend/.env or environment).")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    req = ScoreRequest(
        schema_version=SCHEMA_VERSION,
        from_email="a@b.com",
        urls=["https://testsafebrowsing.appspot.com/s/phishing.html"],
    )
    out = score_message(req)
    assert out.reputation.providers.get("safe_browsing") == "threat"
    assert out.signals.reputation_overlay >= 84.0
    assert out.reputation.contributed is True
    assert "Safe Browsing" in " ".join(out.reasons)

