"""Gemini-first LLM analysis provider — outbound HTTP, redaction, JSON parse.

This module must never raise into the scoring engine. Any provider problems
return a structured status and the engine continues with local scoring.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from app.llm.types import LlmProviderResult, LlmStructuredAnalysis
from app.reputation.guard import (
    llm_cooldown_active,
    record_llm_rate_limit,
    try_reserve_llm_analysis_call,
)
from app.schemas import ScoreRequest
from app.score_logging import log_score_event

_LLM_SUBJECT_MAX = 200
_LLM_SNIPPET_MAX = 900
_LLM_MAX_URL_DOMAINS = 16

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_URL_RE = re.compile(r"https?://\S+", re.I)
_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
)

_SYSTEM_PROMPT = """You are a phishing and social-engineering triage assistant.
Analyze only the metadata and redacted text provided.
Respond with a single JSON object (no markdown fences) using exactly these keys:
risk_points (number 0-100),
confidence (number 0-1),
categories (array of zero or more from: credential_theft, financial_fraud, malware_attachment, impersonation, urgency, sensitive_info_request),
reasons (array of up to 6 short user-safe explanations; never quote secrets or full URLs),
should_not_override_reputation (boolean; must be true).
Do not include chain-of-thought. English only."""


def _env_bool_opt_out(name: str) -> bool:
    """Unset or any value other than false/0/no/off => enabled."""
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return True
    return raw not in {"0", "false", "no", "off"}


def _resolve_api_key() -> str | None:
    """Prefer GEMINI_API_KEY, else fall back to generic LLM_API_KEY."""
    gemini = (os.getenv("GEMINI_API_KEY") or "").strip()
    if gemini:
        return gemini
    generic = (os.getenv("LLM_API_KEY") or "").strip()
    return generic or None


def _domain_from_email(addr: str) -> str | None:
    addr = addr.strip().lower()
    if "@" not in addr:
        return None
    _, _, host = addr.rpartition("@")
    return host.strip() or None


def _normalize_host(host: str) -> str:
    h = host.lower().strip().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _url_domains(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        host = (urlparse(u).hostname or "").strip()
        if not host:
            continue
        norm = _normalize_host(host)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
        if len(out) >= _LLM_MAX_URL_DOMAINS:
            break
    return out


def _redact_text(text: str) -> str:
    s = text
    s = _EMAIL_RE.sub("[REDACTED_EMAIL]", s)
    s = _URL_RE.sub("[REDACTED_URL]", s)
    s = _JWT_RE.sub("[REDACTED_TOKEN]", s)
    s = _LONG_B64_RE.sub("[REDACTED_SECRET]", s)
    s = _CARD_RE.sub("[REDACTED_CARD]", s)
    s = _IPV4_RE.sub("[REDACTED_IP]", s)
    return s


def _truncate(text: str, max_len: int) -> str:
    t = text.strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 3] + "..."


def build_redacted_payload(req: ScoreRequest) -> dict[str, Any]:
    """Privacy-safe bundle for the model — no full URLs or raw auth headers."""
    attachments: list[dict[str, Any]] = []
    for a in req.attachments:
        name = PurePosixPath(a.filename.replace("\\", "/")).name
        attachments.append(
            {
                "filename": name[:120],
                "mime_type": a.mime_type,
                "size_bytes": a.size_bytes,
            },
        )
    return {
        "from_domain": _domain_from_email(req.from_email),
        "reply_to_domain": _domain_from_email(req.reply_to) if req.reply_to else None,
        "display_name_present": bool((req.display_name or "").strip()),
        "subject": _truncate(_redact_text(req.subject), _LLM_SUBJECT_MAX),
        "snippet": _truncate(_redact_text(req.snippet), _LLM_SNIPPET_MAX),
        "url_domains": _url_domains(req.urls),
        "attachment_count": len(req.attachments),
        "attachments": attachments[:12],
    }


def _extract_json_object(text: str) -> dict[str, Any] | None:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.I)
        s = re.sub(r"\s*```$", "", s)
    try:
        data = json.loads(s)
    except json.JSONDecodeError:
        start = s.find("{")
        end = s.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            data = json.loads(s[start : end + 1])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _parse_analysis(raw_text: str) -> LlmStructuredAnalysis | None:
    obj = _extract_json_object(raw_text)
    if obj is None:
        return None
    try:
        return LlmStructuredAnalysis.model_validate(obj)
    except ValidationError:
        return None


def _gemini_model() -> str:
    return (os.getenv("LLM_MODEL") or "gemini-2.0-flash").strip() or "gemini-2.0-flash"


def _llm_timeout() -> httpx.Timeout:
    raw = (os.getenv("LLM_TIMEOUT_SECONDS") or "").strip()
    try:
        total = float(raw) if raw else 2.5
    except ValueError:
        total = 2.5
    return httpx.Timeout(max(1.0, total), connect=min(2.0, total))


def _call_gemini(
    payload: dict[str, Any],
    api_key: str,
    *,
    client: httpx.Client,
    model: str,
) -> tuple[str | None, int, str]:
    """Returns (response_text, latency_ms, error_status)."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    user_content = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    body: dict[str, Any] = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": _SYSTEM_PROMPT + "\n\nInput:\n" + user_content}],
            },
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512,
            "responseMimeType": "application/json",
        },
    }

    t0 = time.perf_counter()
    try:
        resp = client.post(url, params={"key": api_key}, json=body)
    except httpx.TimeoutException:
        ms = int((time.perf_counter() - t0) * 1000)
        return None, ms, "error_timeout"
    except httpx.HTTPError:
        ms = int((time.perf_counter() - t0) * 1000)
        return None, ms, "error_http"

    ms = int((time.perf_counter() - t0) * 1000)
    if resp.status_code == 429:
        record_llm_rate_limit()
        return None, ms, "error_rate_limited"
    if resp.status_code >= 400:
        if resp.status_code in (402, 403) and "quota" in resp.text.lower():
            record_llm_rate_limit()
            return None, ms, "error_rate_limited"
        return None, ms, "error_http"

    try:
        data = resp.json()
    except ValueError:
        return None, ms, "error_invalid_response"

    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return None, ms, "error_invalid_response"
    parts = candidates[0].get("content", {}).get("parts", [])
    if not isinstance(parts, list):
        return None, ms, "error_invalid_response"
    texts: list[str] = []
    for p in parts:
        if isinstance(p, dict) and isinstance(p.get("text"), str):
            texts.append(p["text"])
    if not texts:
        return None, ms, "error_invalid_response"
    return "\n".join(texts), ms, ""


def run_llm_analysis(
    req: ScoreRequest,
    *,
    client: httpx.Client | None = None,
) -> LlmProviderResult:
    """Optional LLM pass. Never raises; returns skip/error status on failure."""
    if not _env_bool_opt_out("LLM_ANALYSIS_ENABLED"):
        return LlmProviderResult("skipped_disabled", latency_ms=0)

    api_key = _resolve_api_key()
    if not api_key:
        return LlmProviderResult("skipped_no_api_key", latency_ms=0)

    if llm_cooldown_active():
        log_score_event("llm_cooldown_skip", provider="llm")
        return LlmProviderResult("skipped_cooldown", latency_ms=0)

    if not try_reserve_llm_analysis_call():
        return LlmProviderResult("skipped_budget", latency_ms=0)

    backend = (os.getenv("LLM_BACKEND") or "gemini").strip().lower()
    if backend not in ("gemini", ""):
        log_score_event("llm_unsupported_backend", backend=backend)
        return LlmProviderResult("skipped_unsupported_backend", latency_ms=0)

    model = _gemini_model()
    payload = build_redacted_payload(req)

    close_client = False
    if client is None:
        client = httpx.Client(timeout=_llm_timeout(), follow_redirects=True)
        close_client = True

    try:
        text, latency_ms, err = _call_gemini(payload, api_key, client=client, model=model)
    finally:
        if close_client:
            client.close()

    if err:
        log_score_event("llm_provider_failure", status=err, latency_ms=latency_ms, model=model)
        return LlmProviderResult(err, latency_ms=latency_ms, model=model)

    if not text:
        log_score_event("llm_provider_failure", status="error_invalid_response", latency_ms=latency_ms)
        return LlmProviderResult("error_invalid_response", latency_ms=latency_ms, model=model)

    analysis = _parse_analysis(text)
    if analysis is None:
        log_score_event("llm_provider_failure", status="error_invalid_json", latency_ms=latency_ms, model=model)
        return LlmProviderResult("error_invalid_json", latency_ms=latency_ms, model=model)

    log_score_event(
        "llm_run",
        status="ok",
        latency_ms=latency_ms,
        risk_points=round(analysis.risk_points, 1),
        model=model,
    )
    return LlmProviderResult("ok", analysis=analysis, latency_ms=latency_ms, model=model)

