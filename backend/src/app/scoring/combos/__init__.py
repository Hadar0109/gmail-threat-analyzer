"""Combination rules package.

Responsible for re-exporting combo evaluation used after atomic signal chunks exist.
"""
from app.scoring.combos.evaluator import ComboResult, evaluate_combos

__all__ = ("ComboResult", "evaluate_combos")
