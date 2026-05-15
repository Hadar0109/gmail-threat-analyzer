"""Unit tests for workflow platform helpers."""

from __future__ import annotations

from app.constants import SCHEMA_VERSION
from app.schemas import ScoreRequest
from app.scoring.parsing.workflow import (
    detect_workflow_context,
    host_is_workflow_platform,
    impersonation_brand_mentions,
)
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation


def test_teams_host_is_workflow_platform() -> None:
    assert host_is_workflow_platform("teams.microsoft.com")


def test_microsoft_dropped_from_impersonation_in_interview_context() -> None:
    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "noreply@comeet.co",
            "subject": "Interview invitation",
            "snippet": "Join the Microsoft Teams meeting for your Au10tix interview.",
            "urls": ["https://teams.microsoft.com/l/meetup-join/abc"],
            "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
    )
    assert detect_workflow_context(req)
    assert not impersonation_brand_mentions(req)
    chunk, findings = evaluate_brand_impersonation(req)
    assert chunk.points == 0.0
    assert not findings
