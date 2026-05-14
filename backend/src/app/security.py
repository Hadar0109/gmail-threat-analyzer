"""HMAC verification, rate limits, and request guards — Phase 4."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import deque
from threading import Lock

from fastapi import HTTPException, Request

from app.constants import HMAC_SIGNATURE_HEADER


def _hmac_secret_bytes() -> bytes | None:
    raw = (os.getenv("HMAC_SECRET") or "").strip()
    return raw.encode("utf-8") if raw else None


def verify_request_hmac(request: Request, body: bytes) -> None:
    """
    When HMAC_SECRET is set, require X-Body-Signature: lowercase hex HMAC-SHA256(secret, raw_body).
    When unset, verification is skipped (local developer ergonomics).
    """
    secret = _hmac_secret_bytes()
    if secret is None:
        return

    provided = (request.headers.get(HMAC_SIGNATURE_HEADER) or "").strip().lower()
    if not provided:
        raise HTTPException(status_code=401, detail="Missing HMAC signature")
    if len(provided) != 64 or any(c not in "0123456789abcdef" for c in provided):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature format")

    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")


class SlidingWindowRateLimiter:
    """Fixed-window style limiter using monotonic timestamps per key."""

    def __init__(self, max_events: int, window_seconds: float) -> None:
        self._max = max_events
        self._window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._events.setdefault(key, deque())
            while dq and dq[0] <= now - self._window:
                dq.popleft()
            if len(dq) >= self._max:
                return False
            dq.append(now)
            return True


score_rate_limiter = SlidingWindowRateLimiter(120, 60.0)


def rate_limit_score_client(request: Request) -> None:
    """Best-effort per-IP cap on POST /v1/score (single-process MVP)."""
    ip = request.client.host if request.client else "unknown"
    if not score_rate_limiter.allow(ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this client; retry later.",
        )
