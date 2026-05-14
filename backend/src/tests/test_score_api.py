"""POST /v1/score — API contract tests (Phases 1–2)."""

from fastapi.testclient import TestClient

from app.constants import REPUTATION_NOTICE_LOCAL_ONLY, SCHEMA_VERSION
from app.main import app

client = TestClient(app)

_MINIMAL_VALID = {
    "schema_version": SCHEMA_VERSION,
    "from_email": "sender@example.com",
}

_REQUIRED_RESPONSE_FIELDS = frozenset(
    {
        "schema_version",
        "score",
        "verdict",
        "confidence",
        "reasons",
        "signals",
        "reputation",
        "reputation_notice",
    },
)


def test_score_valid_request_returns_200() -> None:
    response = client.post("/v1/score", json=_MINIMAL_VALID)
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == SCHEMA_VERSION
    assert isinstance(body["score"], int)
    assert 0 <= body["score"] <= 100


def test_score_invalid_schema_version_returns_validation_error() -> None:
    response = client.post(
        "/v1/score",
        json={**_MINIMAL_VALID, "schema_version": "0.9"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert isinstance(detail, list)
    assert any("schema_version" in str(err.get("loc", ())) for err in detail)
    for err in detail:
        assert "input" not in err


def test_score_unknown_field_returns_validation_error() -> None:
    response = client.post(
        "/v1/score",
        json={**_MINIMAL_VALID, "unexpected": True},
    )
    assert response.status_code == 422


def test_score_response_includes_all_required_fields() -> None:
    response = client.post(
        "/v1/score",
        json={
            **_MINIMAL_VALID,
            "subject": "Hello",
            "snippet": "Please review",
            "urls": ["https://example.com/path"],
            "attachments": [
                {"filename": "a.pdf", "mime_type": "application/pdf", "size_bytes": 1024},
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert _REQUIRED_RESPONSE_FIELDS <= body.keys()
    assert isinstance(body["reasons"], list) and body["reasons"]
    assert isinstance(body["signals"], dict)
    assert isinstance(body["reputation"], dict)
    assert body["reputation_notice"] == REPUTATION_NOTICE_LOCAL_ONLY


def test_score_deterministic_for_same_payload() -> None:
    payload = {**_MINIMAL_VALID, "subject": "Re: invoice"}
    a = client.post("/v1/score", json=payload).json()
    b = client.post("/v1/score", json=payload).json()
    assert a == b


def test_score_optional_authentication_accepted() -> None:
    response = client.post(
        "/v1/score",
        json={
            **_MINIMAL_VALID,
            "authentication": {"spf": "pass", "dkim": "neutral", "dmarc": "fail"},
        },
    )
    assert response.status_code == 200
