"""User-facing explanation layer for score results.

Maps internal detector reason strings to plain-language explanations.
Does not change scoring weights, verdicts, or reputation integrations.
"""

from app.explain.presenter import build_score_explanation
from app.explain.synthesis import synthesize_findings

__all__ = ["build_score_explanation", "synthesize_findings"]
