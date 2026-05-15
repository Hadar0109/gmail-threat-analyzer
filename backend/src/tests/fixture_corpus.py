"""Load labeled ScoreRequest JSON fixtures for regression tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from app.schemas import ScoreRequest, Verdict

FIXTURES_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "scoring"


@dataclass(frozen=True, slots=True)
class LabeledFixture:
    """One labeled scoring example from the fixture corpus."""

    id: str
    label: str
    description: str
    request: ScoreRequest
    expected_verdicts: frozenset[Verdict]
    expected_score_min: int | None
    expected_score_max: int | None


def _parse_verdict_list(raw: list[str]) -> frozenset[Verdict]:
    return frozenset(Verdict(v.strip().lower()) for v in raw)


def _load_fixture_file(path: Path, label: str) -> LabeledFixture:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    fixture_id = data.get("id") or path.stem
    description = str(data.get("description", "")).strip()
    expected = data.get("expected_verdicts")
    if not expected:
        raise ValueError(f"{path}: expected_verdicts is required")
    request = ScoreRequest.model_validate(data["request"])
    return LabeledFixture(
        id=fixture_id,
        label=label,
        description=description,
        request=request,
        expected_verdicts=_parse_verdict_list(expected),
        expected_score_min=data.get("expected_score_min"),
        expected_score_max=data.get("expected_score_max"),
    )


def iter_fixtures(category: str) -> Iterator[LabeledFixture]:
    """Yield fixtures from ``fixtures/scoring/<category>/`` (e.g. phishing, benign)."""
    root = FIXTURES_ROOT / category
    if not root.is_dir():
        return
    for path in sorted(root.glob("*.json")):
        yield _load_fixture_file(path, label=category)


def all_fixtures() -> list[LabeledFixture]:
    return [*iter_fixtures("phishing"), *iter_fixtures("benign")]
