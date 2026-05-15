"""Structured, privacy-safe logging for POST /score (Step 4 hardening)."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger("app.score")


def _json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value
    return str(value)


def log_score_event(event: str, **fields: Any) -> None:
    """Emit one JSON line; never pass request bodies, URLs, or message content."""
    payload: dict[str, Any] = {"event": event}
    for key, val in fields.items():
        if val is None:
            continue
        payload[key] = _json_safe(val)
    logger.info("%s", json.dumps(payload, separators=(",", ":"), sort_keys=True))


def hash_client_host(host: str | None) -> str | None:
    """Short stable fingerprint for rate-limit logs (not a reversible IP log)."""
    if not host or host == "unknown":
        return None
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()
    return digest[:16]
