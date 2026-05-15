"""Combo rule evaluator.

Responsible for matching combo rules and computing capped boost points and reasons.
Does not redefine atomic detectors.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.scoring.combos.context import ScoringContext
from app.scoring.combos.rules import COMBO_RULES
from app.scoring.weights import COMBO_CONTEXT_BOOST_CAP

CONTEXT_BOOST_CAP = COMBO_CONTEXT_BOOST_CAP


@dataclass(frozen=True, slots=True)
class ComboResult:
    boost: float
    reasons: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]


def evaluate_combos(ctx: ScoringContext) -> ComboResult:
    """
    Apply priority-ordered combo rules; cumulative boost is capped.

    Each matched rule contributes its boost until the cap is reached.
    """
    boost = 0.0
    reasons: list[str] = []
    matched: list[str] = []

    for rule in COMBO_RULES:
        if not rule.when(ctx):
            continue
        remaining = CONTEXT_BOOST_CAP - boost
        if remaining <= 0:
            break
        applied = min(rule.boost, remaining)
        boost += applied
        matched.append(rule.id)
        reasons.append(rule.reason)
        if boost >= CONTEXT_BOOST_CAP:
            break

    return ComboResult(boost=boost, reasons=tuple(reasons), matched_rule_ids=tuple(matched))
