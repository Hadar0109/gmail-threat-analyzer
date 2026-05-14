"""POST /v1/score — Phases 1–4 (validation, scoring, optional HMAC, rate limits)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from pydantic import ValidationError

from app.limits import LIMITS
from app.schemas import ScoreRequest, ScoreResponse
from app.scoring.engine import score_message
from app.security import rate_limit_score_client, verify_request_hmac

router = APIRouter(prefix="/v1", tags=["score"])


@router.post("/score", response_model=ScoreResponse)
async def post_score(request: Request) -> ScoreResponse:
    """Score a normalized message feature bundle using the local rules engine + reputation."""
    rate_limit_score_client(request)

    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > LIMITS.MAX_SCORE_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Request body too large")
        except ValueError:
            pass

    raw = await request.body()
    if len(raw) > LIMITS.MAX_SCORE_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Empty request body")

    verify_request_hmac(request, raw)

    try:
        body = ScoreRequest.model_validate_json(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=jsonable_encoder(exc.errors())) from exc

    return score_message(body)
