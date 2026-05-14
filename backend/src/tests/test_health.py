from fastapi.testclient import TestClient

from app.constants import SCHEMA_VERSION
from app.main import app

client = TestClient(app)


def test_health_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["schema_version"] == SCHEMA_VERSION
