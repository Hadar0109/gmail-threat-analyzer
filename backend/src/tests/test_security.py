"""Phase 4 — HMAC, body size, and rate limits on POST /v1/score."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

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
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


def test_hmac_invalid_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HMAC_SECRET", "unit-test-secret")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
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
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    raw = json.dumps(_MINIMAL).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_hmac_current_secret_works_when_previous_also_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    current = b"new-secret"
    previous = b"old-secret"
    monkeypatch.setenv("HMAC_SECRET", current.decode())
    monkeypatch.setenv("HMAC_SECRET_PREVIOUS", previous.decode())
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    raw = json.dumps(_MINIMAL).encode("utf-8")
    sig = _sign(raw, current)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_hmac_accepts_previous_secret_when_both_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    current = b"new-secret"
    previous = b"old-secret"
    monkeypatch.setenv("HMAC_SECRET", current.decode())
    monkeypatch.setenv("HMAC_SECRET_PREVIOUS", previous.decode())
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    raw = json.dumps(_MINIMAL).encode("utf-8")
    sig = _sign(raw, previous)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_hmac_rejects_neither_current_nor_previous(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HMAC_SECRET", "new-secret")
    monkeypatch.setenv("HMAC_SECRET_PREVIOUS", "old-secret")
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
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
    detail = r.json()["detail"]
    assert detail["code"] == "hmac_invalid"


def test_production_without_hmac_secret_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("HMAC_SECRET", raising=False)
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "service_unavailable"


def test_production_hmac_secret_required_even_if_previous_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """HMAC_SECRET_PREVIOUS does not satisfy production bootstrap; HMAC_SECRET must be set."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("HMAC_SECRET", raising=False)
    monkeypatch.setenv("HMAC_SECRET_PREVIOUS", "orphan-previous-only")
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "service_unavailable"


def test_production_with_hmac_missing_signature_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("HMAC_SECRET", "unit-test-secret")
    raw = json.dumps(_MINIMAL).encode("utf-8")
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 401


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


def _replay_payload(*, issued_at: int | None = None, request_id: str | None = None) -> dict:
    rid = request_id if request_id is not None else str(uuid.uuid4())
    ts = issued_at if issued_at is not None else int(time.time() * 1000)
    return {
        "schema_version": SCHEMA_VERSION,
        "issued_at": ts,
        "request_id": rid,
        "from_email": "sender@example.com",
    }


def test_production_missing_replay_fields_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    raw = json.dumps(_MINIMAL).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "replay_fields_required"


def test_production_expired_issued_at_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    old = int(time.time() * 1000) - 400_000
    payload = _replay_payload(issued_at=old)
    raw = json.dumps(payload).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "issued_at_invalid"


def test_production_future_issued_at_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    future = int(time.time() * 1000) + 400_000
    payload = _replay_payload(issued_at=future)
    raw = json.dumps(payload).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "issued_at_invalid"


def test_production_fresh_replay_fields_returns_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    payload = _replay_payload()
    raw = json.dumps(payload).encode("utf-8")
    sig = _sign(raw, secret)
    r = client.post(
        "/v1/score",
        content=raw,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 200


def test_production_duplicate_request_id_returns_409(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    rid = str(uuid.uuid4())
    payload = _replay_payload(request_id=rid)
    raw = json.dumps(payload).encode("utf-8")
    sig = _sign(raw, secret)
    headers = {"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig}
    assert client.post("/v1/score", content=raw, headers=headers).status_code == 200
    dup = client.post("/v1/score", content=raw, headers=headers)
    assert dup.status_code == 409
    assert dup.json()["detail"]["code"] == "replay_duplicate"


def test_hmac_invalid_when_body_changed_after_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    """issued_at and request_id are inside the signed bytes; tampering invalidates the MAC."""
    secret = b"unit-test-secret"
    monkeypatch.setenv("HMAC_SECRET", secret.decode())
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    p1 = _replay_payload(issued_at=17_000_000_000_000)
    p2 = {**p1, "issued_at": 17_000_000_000_001}
    raw_signed = json.dumps(p1).encode("utf-8")
    raw_sent = json.dumps(p2).encode("utf-8")
    sig = _sign(raw_signed, secret)
    r = client.post(
        "/v1/score",
        content=raw_sent,
        headers={"Content-Type": "application/json", HMAC_SIGNATURE_HEADER: sig},
    )
    assert r.status_code == 401


def test_dev_partial_replay_fields_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("HMAC_SECRET", raising=False)
    r = client.post(
        "/v1/score",
        json={**_MINIMAL, "issued_at": int(time.time() * 1000)},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "replay_fields_required"
