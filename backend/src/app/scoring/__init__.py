"""Scoring package.

Responsible for exporting score_message as the public scoring entry point.
"""
from app.scoring.engine import score_message

__all__ = ["score_message"]
