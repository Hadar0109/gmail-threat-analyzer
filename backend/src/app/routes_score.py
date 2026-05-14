"""POST /v1/score — Phases 1–4 (validation, scoring, optional HMAC, rate limits)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from pydantic import ValidationError

from app.limits import LIMITS
from app.score_errors import score_public_http_exception
from app.score_logging import log_score_event
from app.schemas import ScoreRequest, ScoreResponse
from app.scoring.engine import score_message
from app.security import (
    assert_score_route_hmac_requirements,
    rate_limit_score_client,
    verify_request_hmac,
    verify_score_request_replay,
)

router = APIRouter(prefix="/v1", tags=["score"])

_score_log = logging.getLogger("app.score")


@router.post("/score", response_model=ScoreResponse)
async def post_score(request: Request) -> ScoreResponse:
    """Score a normalized message feature bundle using the local rules engine + reputation."""
    rate_limit_score_client(request)
    assert_score_route_hmac_requirements()

    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > LIMITS.MAX_SCORE_BODY_BYTES:
                log_score_event("body_too_large", content_length_header=cl)
                raise score_public_http_exception("body_too_large")
        except ValueError:
            pass

    raw = await request.body()
    if len(raw) > LIMITS.MAX_SCORE_BODY_BYTES:
        log_score_event("body_too_large", body_bytes=len(raw))
        raise score_public_http_exception("body_too_large")
    if not raw.strip():
        log_score_event("empty_body")
        raise score_public_http_exception("empty_body")

    verify_request_hmac(request, raw)

    try:
        body = ScoreRequest.model_validate_json(raw)
    except ValidationError as exc:
        errs = exc.errors()
        first = errs[0] if errs else {}
        loc = first.get("loc")
        log_score_event(
            "validation_failed",
            error_count=len(errs),
            first_loc="/".join(str(x) for x in loc) if isinstance(loc, tuple) else None,
        )
        raise score_public_http_exception("validation_failed") from exc

    verify_score_request_replay(body)

    try:
        return score_message(body)
    except Exception:
        _score_log.exception("score_engine_unhandled")
        raise score_public_http_exception("internal_error")
