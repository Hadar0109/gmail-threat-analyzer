"""In-process global reputation budget and vendor cooldown (Step 5 — no Redis/DB)."""

from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock

from app.api.score_logging import log_score_event

_lock = Lock()
_sb_calls: deque[float] = deque()
_vt_calls: deque[float] = deque()
_sb_cooldown_until = 0.0
_vt_cooldown_until = 0.0


def _env_float(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _window_seconds() -> float:
    return max(5.0, _env_float("REPUTATION_BUDGET_WINDOW_SECONDS", 60.0))


def _max_sb_per_window() -> int:
    return max(0, _env_int("REPUTATION_BUDGET_MAX_SB_CALLS", 40))


def _max_vt_per_window() -> int:
    return max(0, _env_int("REPUTATION_BUDGET_MAX_VT_CALLS", 180))


def _sb_cooldown_seconds() -> float:
    return max(15.0, _env_float("REPUTATION_SB_COOLDOWN_SECONDS", 90.0))


def _vt_cooldown_seconds() -> float:
    return max(15.0, _env_float("REPUTATION_VT_COOLDOWN_SECONDS", 90.0))


def _prune(dq: deque[float], now: float, window: float) -> None:
    while dq and dq[0] <= now - window:
        dq.popleft()


def safe_browsing_cooldown_active() -> bool:
    with _lock:
        return time.monotonic() < _sb_cooldown_until


def virustotal_cooldown_active() -> bool:
    with _lock:
        return time.monotonic() < _vt_cooldown_until


def record_safe_browsing_rate_limit() -> None:
    global _sb_cooldown_until
    until = time.monotonic() + _sb_cooldown_seconds()
    with _lock:
        _sb_cooldown_until = max(_sb_cooldown_until, until)
    log_score_event("reputation_rate_limited", provider="safe_browsing", cooldown_s=round(_sb_cooldown_seconds(), 1))


def record_virustotal_rate_limit() -> None:
    global _vt_cooldown_until
    until = time.monotonic() + _vt_cooldown_seconds()
    with _lock:
        _vt_cooldown_until = max(_vt_cooldown_until, until)
    log_score_event("reputation_rate_limited", provider="virustotal", cooldown_s=round(_vt_cooldown_seconds(), 1))


def try_reserve_safe_browsing_call() -> bool:
    """Return True if a Safe Browsing batch call may proceed (and record it)."""
    window = _window_seconds()
    cap = _max_sb_per_window()
    if cap <= 0:
        return False
    now = time.monotonic()
    with _lock:
        _prune(_sb_calls, now, window)
        if len(_sb_calls) >= cap:
            log_score_event(
                "reputation_budget_exhausted",
                provider="safe_browsing",
                window_s=round(window, 1),
                cap=cap,
            )
            return False
        _sb_calls.append(now)
        return True


def try_reserve_virustotal_calls(requested: int) -> int:
    """
    Reserve up to `requested` VT URL lookups in the current window.
    Returns how many calls were reserved (0..requested).
    """
    window = _window_seconds()
    cap = _max_vt_per_window()
    if cap <= 0 or requested <= 0:
        return 0
    now = time.monotonic()
    permitted = 0
    with _lock:
        _prune(_vt_calls, now, window)
        for _ in range(requested):
            if len(_vt_calls) >= cap:
                log_score_event(
                    "reputation_budget_exhausted",
                    provider="virustotal",
                    window_s=round(window, 1),
                    cap=cap,
                    requested=requested,
                    permitted=permitted,
                )
                break
            _vt_calls.append(now)
            permitted += 1
    return permitted


def reset_reputation_guard_for_testing() -> None:
    """Clear all guard state (unit tests only)."""
    global _sb_cooldown_until, _vt_cooldown_until
    with _lock:
        _sb_calls.clear()
        _vt_calls.clear()
        _sb_cooldown_until = 0.0
        _vt_cooldown_until = 0.0
