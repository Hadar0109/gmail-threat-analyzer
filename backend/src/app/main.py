from fastapi import FastAPI

from app.constants import SCHEMA_VERSION
from app.routes_score import router as score_router

app = FastAPI(
    title="Gmail Malicious Email Scorer",
    description="Stateless scoring API for the Gmail add-on (MVP).",
    version="0.1.0",
)

app.include_router(score_router)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe for deploy targets and local uvicorn runs."""
    return {"status": "ok", "schema_version": SCHEMA_VERSION}
