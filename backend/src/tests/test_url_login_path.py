"""URL login-path tests.

Responsible for login-like URL path tagging used in URL and content corroboration.
"""
from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.signals.urls import url_tags


def test_login_path_matches_terminal_login_segment() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "a@b.com",
            "urls": ["https://secure-account-check-example.com/login"],
        },
    )
    assert "login_like_path" in url_tags(req)
