"""Unit tests for MessageFeatures extraction."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.features.extract import MessageFeatures


def test_message_features_parses_reply_to_angle_addr() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "team@acme.com",
            "reply_to": "Payments <payee@other.net>",
            "subject": "Hi",
            "body_text_for_scoring": "Wire transfer due today.",
        },
    )
    features = MessageFeatures.from_request(req)
    assert features.reply_to_email == "payee@other.net"
    assert features.reply_to_domain == "other.net"
    assert "wire transfer" in features.scoring_text.lower()
