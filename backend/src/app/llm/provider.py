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

_LLM_TIMEOUT_DEFAULT_S = 8.0
_LLM_RESPONSE_PREVIEW_MAX = 320
_PLACEHOLDER_KEY_MARKERS = (
    "change-me",
    "your-api-key",
    "your_api_key",
    "insert-key",
    "placeholder",
    "xxx",
)

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


def _env_str(name: str) -> str:
    """Read env var; strip whitespace and optional surrounding quotes from .env files."""
    raw = (os.getenv(name) or "").strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        raw = raw[1:-1].strip()
    return raw


def _env_bool_opt_out(name: str) -> bool:
    """Unset or any value other than false/0/no/off/disabled => enabled."""
    raw = _env_str(name).lower()
    if not raw:
        return True
    return raw not in {"0", "false", "no", "off", "disabled"}


def _is_usable_api_key(key: str) -> bool:
    k = key.strip()
    # Google AI keys are typically 39 chars (AIza…); allow shorter only in unit tests.
    if len(k) < 8:
        return False
    low = k.lower()
    if low in {"", "none", "null", "undefined", "unset"}:
        return False
    return not any(marker in low for marker in _PLACEHOLDER_KEY_MARKERS)


def _resolve_api_key() -> str | None:
    """Prefer GEMINI_API_KEY, else fall back to generic LLM_API_KEY."""
    for name in ("GEMINI_API_KEY", "LLM_API_KEY"):
        candidate = _env_str(name)
        if candidate and _is_usable_api_key(candidate):
            return candidate
    return None


def _log_llm_skip(status: str, **fields: Any) -> None:
    log_score_event("llm_skip", status=status, **fields)


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
        filename = (a.filename or "").replace("\\", "/")
        name = PurePosixPath(filename).name if filename else "attachment"
        attachments.append(
            {
                "filename": name[:120],
                "mime_type": a.mime_type or "application/octet-stream",
                "size_bytes": a.size_bytes,
            },
        )
    subject_raw = req.subject if req.subject is not None else ""
    snippet_raw = req.snippet if req.snippet is not None else ""
    return {
        "from_domain": _domain_from_email(req.from_email),
        "reply_to_domain": _domain_from_email(req.reply_to) if req.reply_to else None,
        "display_name_present": bool((req.display_name or "").strip()),
        "subject": _truncate(_redact_text(subject_raw), _LLM_SUBJECT_MAX),
        "snippet": _truncate(_redact_text(snippet_raw), _LLM_SNIPPET_MAX),
        "url_domains": _url_domains(list(req.urls or [])),
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


def _sanitize_response_preview(raw_text: str, *, max_len: int = _LLM_RESPONSE_PREVIEW_MAX) -> str:
    return _sanitize_gemini_error_message(raw_text, max_len=max_len)


def _parse_analysis(
    raw_text: str,
    *,
    model: str = "",
    latency_ms: int = 0,
) -> LlmStructuredAnalysis | None:
    obj = _extract_json_object(raw_text)
    if obj is None:
        log_score_event(
            "llm_parse_failure",
            reason="json_extract_failed",
            response_preview=_sanitize_response_preview(raw_text),
            model=model,
            latency_ms=latency_ms,
        )
        return None
    try:
        return LlmStructuredAnalysis.model_validate(obj)
    except ValidationError as exc:
        field_errors = [
            f"{'.'.join(str(p) for p in err.get('loc', ()))}:{err.get('type', '')}"
            for err in exc.errors()[:6]
        ]
        log_score_event(
            "llm_parse_failure",
            reason="pydantic_validation",
            validation_errors=",".join(field_errors),
            response_preview=_sanitize_response_preview(raw_text),
            model=model,
            latency_ms=latency_ms,
        )
        return None


def _gemini_model() -> str:
    return _env_str("LLM_MODEL") or "gemini-2.0-flash"


def _llm_timeout() -> httpx.Timeout:
    raw = _env_str("LLM_TIMEOUT_SECONDS")
    try:
        total = float(raw) if raw else _LLM_TIMEOUT_DEFAULT_S
    except ValueError:
        total = _LLM_TIMEOUT_DEFAULT_S
    total = max(3.0, total)
    return httpx.Timeout(total, connect=min(5.0, total))


def _gemini_error_logging_enabled() -> bool:
    """Temporary: logs on by default; set LLM_GEMINI_DEBUG=false to silence after triage."""
    return _env_str("LLM_GEMINI_DEBUG").lower() != "false"


def _sanitize_gemini_error_message(message: str, *, max_len: int = 200) -> str:
    """Strip secrets/PII from provider error text before logging."""
    s = message.strip()
    s = _EMAIL_RE.sub("[REDACTED_EMAIL]", s)
    s = _URL_RE.sub("[REDACTED_URL]", s)
    s = re.sub(r"\bAIza[0-9A-Za-z_-]{20,}\b", "[REDACTED_API_KEY]", s)
    s = re.sub(r"\bkey[=:]\s*\S+", "key=[REDACTED]", s, flags=re.I)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _parse_gemini_error_block(resp: httpx.Response) -> tuple[int | None, str | None, str]:
    """Returns (error.code, error.status, sanitized message summary)."""
    try:
        data = resp.json()
    except ValueError:
        return None, None, _sanitize_gemini_error_message(resp.text[:500])
    err = data.get("error")
    if not isinstance(err, dict):
        return None, None, ""
    code_raw = err.get("code")
    code = int(code_raw) if isinstance(code_raw, int) else None
    status = err.get("status")
    gemini_status = status.strip() if isinstance(status, str) and status.strip() else None
    msg = err.get("message")
    summary = _sanitize_gemini_error_message(msg) if isinstance(msg, str) else ""
    return code, gemini_status, summary


def _gemini_should_record_rate_limit(http_status: int, gemini_status: str | None) -> bool:
    """Only true quota / rate-limit signals — not auth, model, or generic 403 text."""
    if http_status == 429:
        return True
    return (gemini_status or "").upper() == "RESOURCE_EXHAUSTED"


def _map_gemini_http_error(http_status: int, gemini_status: str | None, message: str) -> str:
    if _gemini_should_record_rate_limit(http_status, gemini_status):
        return "error_rate_limited"
    gs = (gemini_status or "").upper()
    msg_l = message.lower()
    if http_status == 404 or gs == "NOT_FOUND":
        return "error_http"
    if http_status in (401, 403) or gs in ("UNAUTHENTICATED", "PERMISSION_DENIED"):
        return "error_auth"
    if http_status == 400 or gs in ("INVALID_ARGUMENT", "FAILED_PRECONDITION"):
        if "api key" in msg_l or "api_key" in msg_l or gs == "INVALID_ARGUMENT":
            return "error_auth"
        return "error_http"
    return "error_http"


def _log_gemini_call_debug(
    *,
    http_status: int,
    gemini_error_status: str | None,
    gemini_error_message: str,
    mapped_status: str,
    rate_limit_recorded: bool,
    latency_ms: int,
    model: str,
) -> None:
    log_score_event(
        "gemini_call_debug",
        http_status=http_status,
        gemini_error_status=gemini_error_status or "",
        gemini_error_message=gemini_error_message,
        mapped_status=mapped_status,
        rate_limit_recorded=rate_limit_recorded,
        latency_ms=latency_ms,
        model=model,
    )


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
        log_score_event(
            "llm_provider_failure",
            status="error_timeout",
            latency_ms=ms,
            model=model,
            timeout_s=round(_llm_timeout().read or _LLM_TIMEOUT_DEFAULT_S, 1),
        )
        return None, ms, "error_timeout"
    except httpx.HTTPError as exc:
        ms = int((time.perf_counter() - t0) * 1000)
        log_score_event(
            "llm_provider_failure",
            status="error_http",
            latency_ms=ms,
            model=model,
            transport_error=type(exc).__name__,
        )
        return None, ms, "error_http"

    ms = int((time.perf_counter() - t0) * 1000)
    if resp.status_code >= 400:
        _, gemini_status, err_summary = _parse_gemini_error_block(resp)
        mapped = _map_gemini_http_error(resp.status_code, gemini_status, err_summary)
        rate_limit_recorded = False
        if _gemini_should_record_rate_limit(resp.status_code, gemini_status):
            record_llm_rate_limit()
            rate_limit_recorded = True
        if _gemini_error_logging_enabled():
            _log_gemini_call_debug(
                http_status=resp.status_code,
                gemini_error_status=gemini_status,
                gemini_error_message=err_summary,
                mapped_status=mapped,
                rate_limit_recorded=rate_limit_recorded,
                latency_ms=ms,
                model=model,
            )
        return None, ms, mapped

    try:
        data = resp.json()
    except ValueError:
        log_score_event(
            "llm_provider_failure",
            status="error_invalid_response",
            latency_ms=ms,
            model=model,
            detail="response_not_json",
        )
        return None, ms, "error_invalid_response"

    text, invalid_detail = _extract_gemini_text(data)
    if text:
        return text, ms, ""
    log_score_event(
        "llm_provider_failure",
        status="error_invalid_response",
        latency_ms=ms,
        model=model,
        detail=invalid_detail or "empty_candidates",
    )
    return None, ms, "error_invalid_response"


def _extract_gemini_text(data: dict[str, Any]) -> tuple[str | None, str | None]:
    """Parse Gemini generateContent JSON. Returns (text, diagnostic) when text is missing."""
    prompt_feedback = data.get("promptFeedback")
    if isinstance(prompt_feedback, dict):
        block = prompt_feedback.get("blockReason")
        if isinstance(block, str) and block.strip():
            return None, f"prompt_blocked:{block.strip()}"

    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return None, "no_candidates"

    first = candidates[0]
    if not isinstance(first, dict):
        return None, "candidate_not_object"

    finish = first.get("finishReason")
    finish_s = finish.strip() if isinstance(finish, str) else ""
    if finish_s and finish_s not in {"STOP", "MAX_TOKENS"}:
        return None, f"finish_reason:{finish_s}"

    content = first.get("content")
    if not isinstance(content, dict):
        return None, "missing_content"

    parts = content.get("parts")
    if not isinstance(parts, list):
        return None, "missing_parts"

    texts: list[str] = []
    for p in parts:
        if isinstance(p, dict) and isinstance(p.get("text"), str):
            texts.append(p["text"])
    if texts:
        return "\n".join(texts), None
    if finish_s == "MAX_TOKENS":
        return None, "max_tokens_no_text"
    return None, "empty_parts"


def run_llm_analysis(
    req: ScoreRequest,
    *,
    client: httpx.Client | None = None,
) -> LlmProviderResult:
    """Optional LLM pass. Never raises; returns skip/error status on failure."""
    if not _env_bool_opt_out("LLM_ANALYSIS_ENABLED"):
        _log_llm_skip("skipped_disabled")
        return LlmProviderResult("skipped_disabled", latency_ms=0)

    api_key = _resolve_api_key()
    if not api_key:
        has_gemini = bool(_env_str("GEMINI_API_KEY"))
        has_llm = bool(_env_str("LLM_API_KEY"))
        _log_llm_skip(
            "skipped_no_api_key",
            gemini_key_set=has_gemini,
            llm_key_set=has_llm,
        )
        return LlmProviderResult("skipped_no_api_key", latency_ms=0)

    if llm_cooldown_active():
        _log_llm_skip("skipped_cooldown")
        return LlmProviderResult("skipped_cooldown", latency_ms=0)

    if not try_reserve_llm_analysis_call():
        _log_llm_skip("skipped_budget")
        return LlmProviderResult("skipped_budget", latency_ms=0)

    backend = _env_str("LLM_BACKEND").lower() or "gemini"
    if backend not in ("gemini", ""):
        _log_llm_skip("skipped_unsupported_backend", backend=backend)
        return LlmProviderResult("skipped_unsupported_backend", latency_ms=0)

    model = _gemini_model()
    try:
        payload = build_redacted_payload(req)
    except Exception as exc:
        _log_llm_skip("skipped_payload_error", error_type=type(exc).__name__)
        return LlmProviderResult("error_http", latency_ms=0, model=model)

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
        return LlmProviderResult("error_invalid_response", latency_ms=latency_ms, model=model)

    analysis = _parse_analysis(text, model=model, latency_ms=latency_ms)
    if analysis is None:
        log_score_event(
            "llm_provider_failure",
            status="error_invalid_json",
            latency_ms=latency_ms,
            model=model,
        )
        return LlmProviderResult("error_invalid_json", latency_ms=latency_ms, model=model)

    log_score_event(
        "llm_run",
        status="ok",
        latency_ms=latency_ms,
        risk_points=round(analysis.risk_points, 1),
        model=model,
    )
    return LlmProviderResult("ok", analysis=analysis, latency_ms=latency_ms, model=model)

