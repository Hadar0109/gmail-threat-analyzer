"""Schema validation tests.

Responsible for Pydantic model validation rules on ScoreRequest/ScoreResponse.
"""
import pytest
from pydantic import ValidationError

from app.constants import SCHEMA_VERSION
from app.limits import LIMITS
from app.schemas import ScoreRequest


def test_score_request_rejects_empty_url_item() -> None:
    with pytest.raises(ValidationError):
        ScoreRequest(
            schema_version=SCHEMA_VERSION,
            from_email="x@y.z",
            urls=["https://a.com", "   "],
        )


def test_score_request_rejects_too_many_urls() -> None:
    urls = [f"https://example.com/{i}" for i in range(LIMITS.MAX_URL_ITEMS + 1)]
    with pytest.raises(ValidationError):
        ScoreRequest(schema_version=SCHEMA_VERSION, from_email="x@y.z", urls=urls)
