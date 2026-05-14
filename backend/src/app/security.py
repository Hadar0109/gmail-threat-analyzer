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
from app.score_errors import score_public_http_exception
from app.score_logging import hash_client_host, log_score_event
from app.schemas import ScoreRequest


def is_production_environment() -> bool:
    """True when deploy is marked production (Render / public). Not set locally by default."""
    env = (os.getenv("ENVIRONMENT") or os.getenv("ENV") or "").strip().lower()
    return env in {"production", "prod"}


def assert_score_route_hmac_requirements() -> None:
    """
    In production, POST /v1/score must never run as an unsigned open API.
    Requires HMAC_SECRET to be set (HMAC_SECRET_PREVIOUS alone is not enough).
    Actual signature verification runs after the body is read.
    """
    if not is_production_environment():
        return
    if _hmac_secret_bytes() is None:
        log_score_event(
            "score_hmac_secret_missing_in_production",
            environment="production",
        )
        raise score_public_http_exception("service_unavailable")


def _hmac_secret_bytes() -> bytes | None:
    raw = (os.getenv("HMAC_SECRET") or "").strip()
    return raw.encode("utf-8") if raw else None


def _hmac_previous_secret_bytes() -> bytes | None:
    raw = (os.getenv("HMAC_SECRET_PREVIOUS") or "").strip()
    return raw.encode("utf-8") if raw else None


def verify_request_hmac(request: Request, body: bytes) -> None:
    """
    When HMAC_SECRET is set, require X-Body-Signature: lowercase hex HMAC-SHA256(secret, raw_body).
    If HMAC_SECRET_PREVIOUS is also set, the same header may match either secret (same error text
    on failure; both digests are compared when the previous secret is configured).
    When HMAC_SECRET is unset, verification is skipped (local developer ergonomics).
    """
    secret = _hmac_secret_bytes()
    if secret is None:
        return

    provided = (request.headers.get(HMAC_SIGNATURE_HEADER) or "").strip().lower()
    if not provided:
        log_score_event("hmac_missing", body_bytes=len(body))
        raise score_public_http_exception("hmac_missing")
    if len(provided) != 64 or any(c not in "0123456789abcdef" for c in provided):
        log_score_event("hmac_invalid_format", body_bytes=len(body))
        raise score_public_http_exception("hmac_invalid_format")

    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    prev = _hmac_previous_secret_bytes()
    if prev is None:
        if not hmac.compare_digest(provided, expected):
            log_score_event("hmac_mismatch", body_bytes=len(body))
            raise score_public_http_exception("hmac_invalid")
        return

    expected_prev = hmac.new(prev, body, hashlib.sha256).hexdigest()
    # Bitwise OR so both compare_digest calls run; same detail string either way.
    ok = hmac.compare_digest(provided, expected) | hmac.compare_digest(provided, expected_prev)
    if not ok:
        log_score_event("hmac_mismatch", body_bytes=len(body))
        raise score_public_http_exception("hmac_invalid")


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
        log_score_event(
            "rate_limit_blocked",
            client_fp=hash_client_host(request.client.host if request.client else None),
        )
        raise score_public_http_exception("rate_limited")


class RequestIdReplayCache:
    """
    In-process duplicate detection for request_id values (single-instance deployments).
    Evicts entries older than window_seconds; enforces max_entries under abuse.
    """

    def __init__(self, window_seconds: float, max_entries: int) -> None:
        self._window = window_seconds
        self._max = max_entries
        self._events: deque[tuple[float, str]] = deque()
        self._seen: set[str] = set()
        self._lock = Lock()

    def try_reserve(self, request_id_lower: str) -> bool:
        """Return True if request_id is new; False if duplicate within the TTL window."""
        now = time.monotonic()
        with self._lock:
            while self._events and self._events[0][0] <= now - self._window:
                _, old = self._events.popleft()
                self._seen.discard(old)
            if request_id_lower in self._seen:
                return False
            while len(self._seen) >= self._max and self._events:
                _, old = self._events.popleft()
                self._seen.discard(old)
            self._seen.add(request_id_lower)
            self._events.append((now, request_id_lower))
            return True


def _replay_id_ttl_seconds() -> float:
    raw = (os.getenv("REPLAY_REQUEST_ID_TTL_SECONDS") or "300").strip() or "300"
    return max(30.0, float(raw))


def _replay_id_max_entries() -> int:
    raw = (os.getenv("REPLAY_REQUEST_ID_MAX_ENTRIES") or "50000").strip() or "50000"
    return max(1000, int(raw))


score_request_id_cache = RequestIdReplayCache(
    window_seconds=_replay_id_ttl_seconds(),
    max_entries=_replay_id_max_entries(),
)


def _score_max_skew_ms() -> int:
    raw = (os.getenv("SCORE_MAX_SKEW_SECONDS") or "120").strip() or "120"
    return max(10, int(raw)) * 1000


def _assert_issued_at_fresh(issued_at: int) -> None:
    now_ms = int(time.time() * 1000)
    if abs(now_ms - issued_at) > _score_max_skew_ms():
        log_score_event(
            "issued_at_outside_window",
            skew_ms=abs(now_ms - issued_at),
            max_skew_ms=_score_max_skew_ms(),
        )
        raise score_public_http_exception("issued_at_invalid")


def verify_score_request_replay(req: ScoreRequest) -> None:
    """
    Production: require issued_at + request_id, validate clock skew, reject duplicate request_id.
    Non-production: skip when both absent; when either is set, require both and validate the same way.
    """
    prod = is_production_environment()
    has_ts = req.issued_at is not None
    has_rid = req.request_id is not None

    if prod:
        if not has_ts or not has_rid:
            log_score_event("replay_fields_missing", production=True)
            raise score_public_http_exception("replay_fields_required")
        _assert_issued_at_fresh(req.issued_at)
        rid = req.request_id.lower()
        if not score_request_id_cache.try_reserve(rid):
            log_score_event("replay_rejected", request_id=rid)
            raise score_public_http_exception("replay_duplicate")
        return

    if not has_ts and not has_rid:
        return
    if not has_ts or not has_rid:
        log_score_event("replay_fields_partial")
        raise score_public_http_exception("replay_fields_required")
    _assert_issued_at_fresh(req.issued_at)
    rid = req.request_id.lower()
    if not score_request_id_cache.try_reserve(rid):
        log_score_event("replay_rejected", request_id=rid)
        raise score_public_http_exception("replay_duplicate")
