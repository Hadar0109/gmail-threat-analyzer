"""Contract tests: add-on JSON payloads must validate as ScoreRequest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.constants import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS
from app.schemas import ScoreRequest
from app.scoring.engine import score_message

CONTRACT_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "contract" / "addon"


def _contract_files() -> list[Path]:
    if not CONTRACT_DIR.is_dir():
        return []
    return sorted(CONTRACT_DIR.glob("*.json"))


@pytest.mark.parametrize("path", _contract_files(), ids=lambda p: p.stem)
def test_addon_contract_payload_validates(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    payload = data["payload"]
    req = ScoreRequest.model_validate(payload)
    assert req.schema_version in SUPPORTED_SCHEMA_VERSIONS


@pytest.mark.parametrize("path", _contract_files(), ids=lambda p: p.stem)
def test_addon_contract_payload_scores(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = score_message(ScoreRequest.model_validate(data["payload"]))
    assert out.schema_version == SCHEMA_VERSION
    assert 0 <= out.score <= 100


def test_schema_1_1_still_accepted() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": "1.1",
            "from_email": "a@example.com",
        },
    )
    assert req.schema_version == "1.1"


def test_reply_to_angle_addr_parses_for_sender_heuristics() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": "1.2",
            "from_email": "team@acme.com",
            "reply_to": "Payments <payee@other.net>",
            "subject": "Hello",
        },
    )
    out = score_message(req)
    assert any("Reply-To domain" in r for r in out.reasons)


def test_body_text_for_scoring_used_for_content_detection() -> None:
    """Longer scoring window should surface lexicon hits not present in short snippet."""
    req = ScoreRequest.model_validate(
        {
            "schema_version": "1.2",
            "from_email": "sender@example.com",
            "snippet": "Hello",
            "body_text_for_scoring": "Please wire transfer today. Verify your account now.",
        },
    )
    out = score_message(req)
    assert out.signals.urgency >= 18.0


def test_rejects_invalid_content_flag() -> None:
    with pytest.raises(ValidationError):
        ScoreRequest.model_validate(
            {
                "schema_version": "1.2",
                "from_email": "a@example.com",
                "content_flags": [""],
            },
        )
