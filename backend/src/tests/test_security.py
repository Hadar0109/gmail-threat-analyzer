"""Phase 4 — HMAC, body size, and rate limits on POST /v1/score."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.constants import HMAC_SIGNATURE_HEADER, SCHEMA_VERSION
from app.limits import LIMITS
from app.main import app
from app.security import SlidingWindowRateLimiter, score_rate_limiter

client = TestClient(app)

_MINIMAL = {"schema_version": SCHEMA_VERSION, "from_email": "sender@example.com"}


def _sign(body: bytes, secret: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_hmac_missing_returns_401_when_secret_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HMAC_SECRET", "unit-test-secret")
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_hmac_invalid_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HMAC_SECRET", "unit-test-secret")
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={
            "Content-Type": "application/json",
            HMAC_SIGNATURE_HEADER: "0" * 64,
        },
    )
    assert r.status_code == 401


def test_hmac_valid_returns_200(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    raw = json.dumps(_MINIMAL).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_body_too_large_returns_413() -> None:
    pad = "x" * (LIMITS.MAX_SCORE_BODY_BYTES + 1)
    raw = json.dumps({**_MINIMAL, "snippet": pad}).encode("utf-8")
    assert len(raw) > LIMITS.MAX_SCORE_BODY_BYTES
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_rate_limit_returns_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.security.score_rate_limiter",
        SlidingWindowRateLimiter(max_events=2, window_seconds=300.0),
    )
    for i in range(2):
        r = client.post("/v1/score", json={**_MINIMAL, "subject": f"m{i}"})
        assert r.status_code == 200, r.text
    r = client.post("/v1/score", json={**_MINIMAL, "subject": "blocked"})
    assert r.status_code == 429
    monkeypatch.setattr("app.security.score_rate_limiter", score_rate_limiter)
