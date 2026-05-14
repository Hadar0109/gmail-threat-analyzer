import logging
import os

from fastapi import FastAPI

from app.constants import SCHEMA_VERSION
from app.env_bootstrap import load_backend_dotenv
from app.routes_score import router as score_router

logger = logging.getLogger(__name__)

load_backend_dotenv()

# Temporary startup diagnostics (remove later): do not log secret values.
def _api_key_loaded(name: str) -> bool:
    return bool((os.getenv(name) or "").strip())


logger.info(
    "Safe Browsing API key: %s",
    "loaded" if _api_key_loaded("GOOGLE_SAFE_BROWSING_API_KEY") else "missing",
)
logger.info(
    "VirusTotal API key: %s",
    "loaded" if _api_key_loaded("VIRUSTOTAL_API_KEY") else "missing",
)

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
